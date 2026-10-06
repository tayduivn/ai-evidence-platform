"""Self-verification unit tests for the Mock LLM server."""

import json
import urllib.request
import urllib.error
import pytest
from services.mock_llm.server import MockLLMServer


@pytest.fixture(scope="module")
def mock_server():
    server = MockLLMServer(host="127.0.0.1", port=0)
    server.start()
    yield server
    server.stop()


def test_health_endpoint(mock_server):
    url = f"{mock_server.base_url}/health"
    with urllib.request.urlopen(url) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "healthy"
        assert data["service"] == "mock_llm"


def test_models_catalog(mock_server):
    url = f"{mock_server.base_url}/v1/models"
    with urllib.request.urlopen(url) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        model_ids = [m["id"] for m in data["data"]]
        assert "gpt-4o" in model_ids


def test_chat_completions_sync(mock_server):
    url = f"{mock_server.base_url}/v1/chat/completions"
    payload = json.dumps({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Xin chào AI"}],
        "stream": False
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        body = json.loads(resp.read().decode("utf-8"))
        assert "choices" in body
        assert len(body["choices"]) > 0
        assert body["choices"][0]["message"]["role"] == "assistant"
        assert body["usage"]["total_tokens"] > 0


def test_chat_completions_sse_stream(mock_server):
    url = f"{mock_server.base_url}/v1/chat/completions"
    payload = json.dumps({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hồ sơ vay 500tr"}],
        "stream": True
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    chunks = []
    has_done = False

    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        assert "text/event-stream" in resp.headers.get("Content-Type")

        for line in resp:
            decoded = line.decode("utf-8").strip()
            if decoded.startswith("data: "):
                event_data = decoded[6:]
                if event_data == "[DONE]":
                    has_done = True
                    break
                data_obj = json.loads(event_data)
                chunks.append(data_obj)

    assert len(chunks) > 1
    assert has_done is True
    # Verify accumulated content contains response words
    full_text = "".join(
        c["choices"][0]["delta"].get("content", "")
        for c in chunks
        if "content" in c["choices"][0]["delta"]
    )
    assert len(full_text) > 0


def test_fault_injection_status(mock_server):
    url = f"{mock_server.base_url}/v1/chat/completions"
    payload = json.dumps({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Test Error"}],
        "stream": False
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "X-Mock-Status": "500", "X-Mock-Error": "mock_upstream_crash"}
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req)
    assert exc_info.value.code == 500
    err_body = json.loads(exc_info.value.read().decode("utf-8"))
    assert err_body["error"]["type"] == "mock_upstream_crash"
