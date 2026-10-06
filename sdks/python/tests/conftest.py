"""Pytest fixtures and mock server harnesses for AI Evidence SDK tests."""

import http.server
import json
import threading
from typing import Any, Dict, List
import pytest


class MockGatewayHandler(http.server.BaseHTTPRequestHandler):
    """Configurable mock server handling Ingest and Decision APIs."""

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = {}

        self.server.received_posts.append({"path": self.path, "payload": payload, "headers": dict(self.headers)})

        # Check injected error status
        if getattr(self.server, "injected_status", None):
            self.send_response(self.server.injected_status)
            self.end_headers()
            self.wfile.write(b'{"error":"injected_error"}')
            return

        if self.path == "/api/v1/ml/ingest":
            requires_approval = payload.get("requires_approval", False)
            if requires_approval:
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                dec_id = "dec-ml-mock-998"
                resp = {
                    "status": "PENDING_APPROVAL",
                    "decision_id": dec_id,
                    "correlation_id": payload.get("correlation_id", "corr-mock-1"),
                    "poll_url": f"/api/v1/decisions/{dec_id}/status",
                }
                self.wfile.write(json.dumps(resp).encode("utf-8"))
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                resp = {
                    "status": "INGESTED",
                    "event_id": "evt-mock-001",
                    "correlation_id": payload.get("correlation_id", "corr-mock-1"),
                }
                self.wfile.write(json.dumps(resp).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        self.server.received_gets.append({"path": self.path, "headers": dict(self.headers)})

        if getattr(self.server, "injected_status", None):
            self.send_response(self.server.injected_status)
            self.end_headers()
            self.wfile.write(b'{"error":"injected_error"}')
            return

        if self.path.startswith("/api/v1/decisions/") and self.path.endswith("/status"):
            # Status polling
            status_seq = getattr(self.server, "status_sequence", [])
            idx = getattr(self.server, "status_idx", 0)
            if idx < len(status_seq):
                current_status = status_seq[idx]
                self.server.status_idx += 1
            else:
                current_status = status_seq[-1] if status_seq else "APPROVED"

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "decision_id": "dec-ml-mock-998",
                "status": current_status,
                "correlation_id": "corr-mock-1",
            }
            if current_status == "REJECTED":
                resp["rejection_reason"] = getattr(self.server, "rejection_reason", "Risk score too high")
            elif current_status == "APPROVED":
                resp["signature_hex"] = "abcdef1234567890"

            self.wfile.write(json.dumps(resp).encode("utf-8"))
        elif self.path.startswith("/api/v1/approvals/"):
            # Audit detail
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "decision_id": "dec-ml-mock-998",
                "approval_history": getattr(self.server, "approval_history", []),
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_gateway():
    """Starts a local mock gateway server for testing."""
    server = http.server.HTTPServer(("127.0.0.1", 0), MockGatewayHandler)
    server.received_posts = []
    server.received_gets = []
    server.injected_status = None
    server.status_sequence = ["PENDING", "APPROVED"]
    server.status_idx = 0
    server.approval_history = []
    server.rejection_reason = "Test rejection reason"

    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    server.base_url = f"http://127.0.0.1:{port}"
    server.ingest_url = f"http://127.0.0.1:{port}/api/v1/ml/ingest"

    yield server

    server.shutdown()
    server.server_close()
