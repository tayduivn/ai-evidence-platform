"""Webhook signature verification and callback receiver."""

import hashlib
import hmac
import http.server
import json
import logging
import threading
from typing import Any, Callable, Dict, List, Optional, Union

from ai_evidence_sdk.exceptions import WebhookVerificationError

logger = logging.getLogger("ai_evidence_sdk.approval.webhook")


def verify_webhook_signature(
    payload: Union[bytes, str],
    signature: str,
    secret: Union[bytes, str],
) -> bool:
    """
    Verifies HMAC-SHA256 signature for webhook callbacks in constant time.
    Supports raw hex digest or prefixed signatures (e.g. 'sha256=abcdef...').
    """
    if not signature or not secret:
        return False

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret

    clean_sig = signature.strip()
    if clean_sig.lower().startswith("sha256="):
        clean_sig = clean_sig[7:].strip()

    expected = hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.lower(), clean_sig.lower())


class WebhookReceiver:
    """
    Manages incoming webhook callback registration, signature validation,
    and optional embedded HTTP listener for local development and testing.
    """

    def __init__(self, secret: Union[bytes, str]):
        self._secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self._handlers: List[Callable[[Dict[str, Any]], None]] = []
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def on_event(self, handler: Callable[[Dict[str, Any]], None]) -> None:
        """Registers a callback function invoked on valid incoming webhook events."""
        self._handlers.append(handler)

    def process_payload(
        self,
        payload_bytes: bytes,
        signature: str,
    ) -> bool:
        """
        Validates the webhook signature and dispatches payload to registered handlers.
        Returns True on success, False if signature is invalid.
        """
        if not verify_webhook_signature(payload_bytes, signature, self._secret):
            logger.warning("Webhook HMAC signature validation failed")
            return False

        try:
            data = json.loads(payload_bytes.decode("utf-8"))
        except Exception as ex:
            logger.warning("Failed to decode webhook JSON: %s", ex)
            return False

        for h in self._handlers:
            try:
                h(data)
            except Exception as ex:
                logger.error("Error in webhook event handler: %s", ex)

        return True

    def start_server(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """
        Starts a local HTTP server on a background thread to receive webhook POSTs.
        Returns the allocated port number.
        """
        receiver_instance = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)
                sig = (
                    self.headers.get("X-Signature-SHA256")
                    or self.headers.get("X-Hub-Signature-256")
                    or ""
                )

                if receiver_instance.process_payload(body, sig):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"status":"ok"}')
                else:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"error":"invalid_signature"}')

            def log_message(self, format, *args):
                pass  # Suppress default noisy console logs

        self._server = http.server.HTTPServer((host, port), _Handler)
        allocated_port = self._server.server_address[1]

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="ai-evidence-webhook-receiver",
        )
        self._thread.start()
        return allocated_port

    def stop_server(self) -> None:
        """Stops the embedded HTTP webhook server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
            self._thread = None
