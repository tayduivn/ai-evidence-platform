"""
Mock OpenAI-Compatible LLM Server.

Supports:
- Standard chat completions (HTTP POST /v1/chat/completions)
- Real-time token streaming via Server-Sent Events (SSE)
- Dynamic fault injection (latency delay, HTTP error codes, connection abort)
- Configuration API (/mock/configure)
- Health check (/health) and model catalog (/v1/models)
"""

import argparse
import json
import logging
import sys
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional, Dict, Any

logger = logging.getLogger("mock_llm")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server to support concurrent streaming requests."""
    daemon_threads = True
    allow_reuse_address = True


class MockLLMRequestHandler(BaseHTTPRequestHandler):
    """Request handler supporting OpenAI Chat Completion contracts and SSE streaming."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard stderr request logging unless explicitly configured."""
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {
                "status": "healthy",
                "service": "mock_llm",
                "version": "1.0.0",
                "active_config": self.server.config  # type: ignore
            })
            return

        if self.path in ("/v1/models", "/models"):
            self._send_json(200, {
                "object": "list",
                "data": [
                    {"id": "gpt-4o", "object": "model", "owned_by": "mock"},
                    {"id": "gpt-4o-mini", "object": "model", "owned_by": "mock"},
                    {"id": "vietnamese-finance-llm-v1", "object": "model", "owned_by": "enterprise"}
                ]
            })
            return

        self._send_json(404, {"error": {"message": f"Route not found: {self.path}", "type": "invalid_request_error"}})

    def do_POST(self) -> None:
        # Route configuration endpoint
        if self.path == "/mock/configure":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            try:
                new_conf = json.loads(body)
                self.server.config.update(new_conf)  # type: ignore
                self._send_json(200, {"status": "updated", "config": self.server.config})  # type: ignore
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        if self.path == "/mock/reset":
            self.server.config.clear()  # type: ignore
            self.server.config.update(self.server.default_config)  # type: ignore
            self._send_json(200, {"status": "reset", "config": self.server.config})  # type: ignore
            return

        if self.path not in ("/v1/chat/completions", "/chat/completions"):
            self._send_json(404, {"error": {"message": f"Route not found: {self.path}", "type": "invalid_request_error"}})
            return

        # Read POST body
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        try:
            req_data = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": {"message": "Invalid JSON body", "type": "invalid_request_error"}})
            return

        # Check Fault Injection: Latency Delay
        delay_ms = int(
            self.headers.get("X-Mock-Delay-Ms")
            or req_data.get("mock_delay_ms")
            or self.server.config.get("delay_ms", 0)  # type: ignore
        )
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        # Check Fault Injection: Status Code
        mock_status = int(
            self.headers.get("X-Mock-Status")
            or req_data.get("mock_status")
            or self.server.config.get("status_code", 200)  # type: ignore
        )
        if mock_status != 200:
            error_type = self.headers.get("X-Mock-Error", "mock_injected_error")
            self._send_json(mock_status, {
                "error": {
                    "message": f"Injected mock error with status {mock_status}",
                    "type": error_type,
                    "code": mock_status
                }
            })
            return

        # Check Fault Injection: Connection Drop
        if self.headers.get("X-Mock-Drop") or self.server.config.get("drop_connection"):  # type: ignore
            # Immediately close socket
            self.close_connection = True
            return

        # Extract request parameters
        model = req_data.get("model", "gpt-4o")
        messages = req_data.get("messages", [])
        is_stream = bool(req_data.get("stream", False))

        # Generate synthetic response content
        last_prompt = messages[-1].get("content", "") if messages else "No prompt"
        if isinstance(last_prompt, list):
            # Multimodal prompt format
            last_prompt = " ".join(part.get("text", "") for part in last_prompt if isinstance(part, dict))

        # Determine response text
        custom_reply = self.server.config.get("custom_response")  # type: ignore
        if custom_reply:
            response_text = custom_reply
        elif "vay" in last_prompt.lower():
            response_text = "Hệ thống AI đã phân tích hồ sơ tín dụng. Kết quả: Đủ điều kiện phê duyệt hạn mức 500.000.000 VNĐ."
        elif "chứng khoán" in last_prompt.lower() or "lệnh" in last_prompt.lower():
            response_text = "Khuyến nghị giao dịch chứng khoán: Khớp lệnh MUA 10.000 cổ phiếu tại mức giá sàn."
        else:
            response_text = f"Xử lý thành công yêu cầu từ model {model}. Kết quả phản hồi hoàn chỉnh."

        comp_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        created_ts = int(time.time())

        # Handle Standard (Non-Streaming) Response
        if not is_stream:
            resp_body = {
                "id": comp_id,
                "object": "chat.completion",
                "created": created_ts,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": response_text
                        },
                        "finish_reason": "stop"
                    }
                ],
                "usage": {
                    "prompt_tokens": max(5, len(last_prompt.split())),
                    "completion_tokens": max(5, len(response_text.split())),
                    "total_tokens": max(10, len(last_prompt.split()) + len(response_text.split()))
                }
            }
            self._send_json(200, resp_body)
            return

        # Handle Server-Sent Events (SSE) Streaming Response
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        self.close_connection = True

        # Split into realistic token chunks
        words = response_text.split(" ")
        chunk_delay_ms = int(
            self.headers.get("X-Mock-Chunk-Delay-Ms")
            or self.server.config.get("chunk_delay_ms", 5)  # type: ignore
        )

        try:
            # Initial role chunk
            first_chunk = {
                "id": comp_id,
                "object": "chat.completion.chunk",
                "created": created_ts,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": ""},
                        "finish_reason": None
                    }
                ]
            }
            self._write_sse_event(first_chunk)

            # Subsequent content tokens
            for i, word in enumerate(words):
                token_text = word if i == 0 else f" {word}"
                chunk = {
                    "id": comp_id,
                    "object": "chat.completion.chunk",
                    "created": created_ts,
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": token_text},
                            "finish_reason": None
                        }
                    ]
                }
                self._write_sse_event(chunk)
                if chunk_delay_ms > 0:
                    time.sleep(chunk_delay_ms / 1000.0)

            # Terminal chunk with finish_reason: stop
            final_chunk = {
                "id": comp_id,
                "object": "chat.completion.chunk",
                "created": created_ts,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": "stop"
                    }
                ]
            }
            self._write_sse_event(final_chunk)

            # Terminal [DONE] sentinel
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            logger.debug("Client disconnected during SSE stream transmission.")

    def _write_sse_event(self, data_obj: Dict[str, Any]) -> None:
        payload = f"data: {json.dumps(data_obj, ensure_ascii=False)}\n\n".encode("utf-8")
        self.wfile.write(payload)
        self.wfile.flush()


class MockLLMServer:
    """Manager for embedding or launching the Mock LLM server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.requested_port = port
        self.port = port
        self.server: Optional[ThreadedHTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.default_config: Dict[str, Any] = {
            "delay_ms": 0,
            "status_code": 200,
            "chunk_delay_ms": 2,
            "drop_connection": False,
            "custom_response": None
        }
        self.config: Dict[str, Any] = dict(self.default_config)

    def start(self) -> int:
        """Start server in background thread and return allocated port."""
        self.server = ThreadedHTTPServer((self.host, self.requested_port), MockLLMRequestHandler)
        self.server.config = self.config  # type: ignore
        self.server.default_config = self.default_config  # type: ignore
        self.port = self.server.server_address[1]

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        logger.info(f"MockLLMServer started on http://{self.host}:{self.port}")
        return self.port

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def configure(self, **kwargs: Any) -> None:
        """Update mock settings dynamically."""
        self.config.update(kwargs)

    def reset_config(self) -> None:
        """Reset mock configurations to default."""
        self.config.clear()
        self.config.update(self.default_config)

    def stop(self) -> None:
        """Gracefully shut down server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
            self.thread = None
        logger.info("MockLLMServer stopped.")


def run_server(host: str = "0.0.0.0", port: int = 8090) -> None:
    """CLI entrypoint for standalone foreground execution."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    srv = MockLLMServer(host=host, port=port)
    actual_port = srv.start()
    print(f"Mock LLM Server running at http://{host}:{actual_port} (Press Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping Mock LLM Server...")
        srv.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock OpenAI-compatible LLM Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8090, help="Listening port (default: 8090)")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)
