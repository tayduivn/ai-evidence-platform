# Mock LLM Service

High-performance, zero-dependency OpenAI-compatible mock server designed for:
- AI Gateway reverse proxy integration testing
- Token-by-token SSE streaming pass-through and accumulation verification
- Deterministic fault injection (latency delays, 429/500/503 errors, connection drops)
- Gateway latency benchmarking

## Endpoints

- `GET /health`: Health check and active configuration metadata.
- `GET /v1/models`: Mock model catalog (`gpt-4o`, `gpt-4o-mini`, `vietnamese-finance-llm-v1`).
- `POST /v1/chat/completions`: Chat completion handler supporting standard JSON (`stream: false`) and SSE chunks (`stream: true`).
- `POST /mock/configure`: Dynamically adjust latency delay (`delay_ms`), HTTP status (`status_code`), chunk delays (`chunk_delay_ms`), and custom responses.
- `POST /mock/reset`: Reset all fault injection settings back to default.

## Headers for Fault Injection

| Header | Description |
|---|---|
| `X-Mock-Delay-Ms: <ms>` | Injects artificial latency before responding. |
| `X-Mock-Status: <code>` | Overrides HTTP status code (e.g. 500, 429). |
| `X-Mock-Error: <type>` | Custom error type string in response payload. |
| `X-Mock-Chunk-Delay-Ms: <ms>` | Millisecond delay between streaming SSE chunks. |
| `X-Mock-Drop: 1` | Abruptly drops TCP connection without response. |

## Running Standalone

```bash
python -m services.mock_llm.server --host 127.0.0.1 --port 8090
```
