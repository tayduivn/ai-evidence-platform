"""
Live HTTP Probe: Probing Go AI Gateway binary (gateway.exe) with obfuscated PII over HTTP.
Empirically verifies:
1. Obfuscated CCCD (zero-width, full-width) is masked in forwarded prompt.
2. Obfuscated Phone (zero-width, full-width) is masked in forwarded prompt.
3. Obfuscated Bank Account (zero-width, full-width) is masked in forwarded prompt.
4. Non-PII boundary strings (dates, HTTP status codes, money amounts) are forwarded verbatim.
"""

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GATEWAY_BIN = PROJECT_ROOT / "services" / "gateway" / "gateway.exe"

received_requests = []


class RecordingUpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")
        req_json = json.loads(body)
        received_requests.append(req_json)

        resp = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "Success"},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        }
        payload = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    if not GATEWAY_BIN.exists():
        print(f"[!] Gateway binary not found: {GATEWAY_BIN}")
        sys.exit(1)

    # 1. Start Recording Upstream HTTP Server
    upstream_port = find_free_port()
    upstream_server = HTTPServer(("127.0.0.1", upstream_port), RecordingUpstreamHandler)
    upstream_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    upstream_thread.start()
    print(f"[+] Recording Upstream Server started on port {upstream_port}")

    # 2. Start Gateway on ephemeral port pointing to upstream
    gw_port = find_free_port()
    env = os.environ.copy()
    env["GATEWAY_PORT"] = str(gw_port)
    env["UPSTREAM_LLM_URL"] = f"http://127.0.0.1:{upstream_port}"
    env["LEDGER_QUEUE_CAPACITY"] = "1000"

    gw_proc = subprocess.Popen(
        [str(GATEWAY_BIN)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(PROJECT_ROOT)
    )

    try:
        # 3. Wait for Gateway readiness
        health_url = f"http://127.0.0.1:{gw_port}/health"
        ready = False
        start_wait = time.time()
        while time.time() - start_wait < 10.0:
            try:
                with urllib.request.urlopen(health_url, timeout=1.0) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.1)

        if not ready:
            print("[!] Gateway failed to start within 10s")
            sys.exit(1)

        print(f"[+] Gateway is healthy on port {gw_port}")

        # 4. Craft adversarial test cases
        test_cases = [
            {
                "name": "CCCD_ZeroWidth_And_FullWidth",
                "prompt": "Hồ sơ CCCD: 0\u200b01090012345 và căn cước ００１０９００１２３４５.",
                "expected_contains": ["001******345"],
                "prohibited": ["001090012345", "００１０９００１２３４５"],
            },
            {
                "name": "Phone_ZeroWidth_And_FullWidth",
                "prompt": "SĐT 0\u200b912345678 và hotline ０９１２３４５６７８.",
                "expected_contains": ["091****678"],
                "prohibited": ["0912345678", "０９１２３４５６７８"],
            },
            {
                "name": "Bank_ZeroWidth_And_FullWidth",
                "prompt": "STK: 1\u200b9034567890123 và tài khoản: １９０３４５６７８９０１２３.",
                "expected_contains": ["1903******0123"],
                "prohibited": ["19034567890123", "１９０３４５６７８９０１２３"],
            },
            {
                "name": "Non_PII_Boundaries",
                "prompt": "Hệ thống v0.3.0 ngày 2026-10-06 trả HTTP 200 OK với số tiền 100.000 VND.",
                "expected_contains": ["v0.3.0", "2026-10-06", "HTTP 200 OK", "100.000 VND"],
                "prohibited": ["******", "****"],
            },
        ]

        chat_url = f"http://127.0.0.1:{gw_port}/v1/chat/completions"

        for tc in test_cases:
            print(f"[*] Testing {tc['name']}...")
            req_body = json.dumps({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": tc["prompt"]}],
                "stream": False
            }).encode("utf-8")

            req = urllib.request.Request(
                chat_url,
                data=req_body,
                headers={
                    "Content-Type": "application/json",
                    "X-AI-System-ID": "securities-quant-advisor-v1",
                },
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=5.0) as resp:
                assert resp.status == 200, f"Expected 200, got {resp.status}"

            # Inspect what upstream recorded
            assert len(received_requests) > 0, "Upstream received no request"
            last_req = received_requests[-1]
            upstream_messages = last_req.get("messages", [])
            assert len(upstream_messages) > 0, "No messages received upstream"
            forwarded_content = upstream_messages[0].get("content", "")

            print(f"    Forwarded prompt: {forwarded_content}")

            # Verify expected masks / values
            for exp in tc["expected_contains"]:
                assert exp in forwarded_content, f"[{tc['name']}] Missing expected '{exp}' in forwarded content: {forwarded_content}"

            # Verify prohibited unmasked strings
            for proh in tc["prohibited"]:
                assert proh not in forwarded_content, f"[{tc['name']}] Prohibited string '{proh}' leaked upstream!"

            print(f"    [+] {tc['name']} PASSED")

        print("\n[SUCCESS] All Live Gateway HTTP PII obfuscation tests PASSED!\n")

    finally:
        # Clean up processes
        try:
            gw_proc.terminate()
            gw_proc.wait(timeout=3.0)
        except Exception:
            gw_proc.kill()
        upstream_server.shutdown()


if __name__ == "__main__":
    main()
