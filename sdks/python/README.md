# AI Evidence Python SDK (`ai_evidence_sdk`)

The official Python client library for the **AI Evidence & Accountability Platform**. Provides tamper-evident logging, sub-5ms non-blocking queues, resilient background micro-batch delivery, human-in-the-loop approval workflows, and Vietnamese PII scanning.

## Features

- **Non-Blocking Ingestion SLA (< 5.0ms)**: Guaranteed sub-5ms return time (typically < 50µs) for `log_decision()`.
- **Zero Caller Exceptions**: Never disrupts critical machine learning inference threads even during network partitions or backend outages.
- **Thread-Safe Bounded Queue**: Bounded buffer with configurable overflow policies (`DROP_OLDEST`, `DROP_NEWEST`) and atomic drop metrics.
- **Daemon Delivery Worker**: Micro-batching worker with persistent HTTP keep-alive and full jitter exponential backoff.
- **Human-in-the-Loop Approvals**: `request_approval()` returning dict-compatible `ApprovalHandle` with `.wait()` and `.poll()`.
- **4-Eyes Principle Polling**: Supports multi-stage review workflows (`PENDING`, `AWAITING_SECOND_APPROVAL`, `APPROVED`, `REJECTED`, `EXPIRED`).
- **Vietnamese PII Protection**: Local scanner matching Go Gateway regexes for CCCD (12-digit), domestic & international phone numbers, and bank accounts.
- **Webhook Integration**: HMAC-SHA256 signature verification and asynchronous callback listener.
- **Zero Runtime Dependencies**: Uses Python standard library only.

## Quick Start

### 1. Audit-Only Ingestion (< 5.0ms Non-Blocking)

```python
from ai_evidence_sdk import EvidenceClient, MLDecisionEvent

client = EvidenceClient(ingest_url="http://127.0.0.1:8080/api/v1/ml/ingest")

# Log decision using dict or MLDecisionEvent
event = {
    "ai_system_id": "credit-scoring-xgboost",
    "model_version": "v2.1.0",
    "score": 745.5,
    "decision": "APPROVE_LOAN_500M",
    "features": {"income": 45000000, "debt_ratio": 0.28},
}

success = client.log_decision(event)
print(f"Enqueued: {success}")

# Gracefully flush and close
client.close()
```

### 2. Human-in-the-Loop Approval Workflow

```python
from ai_evidence_sdk import EvidenceClient

client = EvidenceClient(ingest_url="http://127.0.0.1:8080/api/v1/ml/ingest")

# Request review for high-risk decision
handle = client.request_approval(
    {
        "ai_system_id": "credit-scoring-xgboost",
        "score": 820.0,
        "amount": 1000000000,
        "creator_id": "analyst-01",
    }
)

# Access ticket metadata like a dict (backward-compatible)
print("Status:", handle["status"])  # "PENDING_APPROVAL"
print("Decision ID:", handle["decision_id"])
print("Poll URL:", handle["poll_url"])

# Wait synchronously for 4-Eyes review outcome
result = handle.wait(timeout=30.0)
if result.is_approved:
    print("Decision APPROVED! Signature:", result.signature_hex)
else:
    print("Decision REJECTED / EXPIRED:", result.rejection_reason)

client.close()
```

### 3. Vietnamese PII Pre-Validation

```python
from ai_evidence_sdk.pii import PIIValidator

payload = {
    "customer": "Nguyen Van A",
    "note": "CCCD 001090012345, SĐT 0912345678, STK 123456789012"
}

masked, detected = PIIValidator.scan_dict(payload)
print(detected)  # ['BANK_ACCOUNT', 'CCCD', 'PHONE']
print(masked["note"])  # 'CCCD 001******345, SĐT 091****678, STK 1234******9012'
```

### 4. Webhook Signature Verification

```python
from ai_evidence_sdk.approval import verify_webhook_signature

is_valid = verify_webhook_signature(
    payload=raw_post_body_bytes,
    signature=headers["X-Signature-SHA256"],
    secret="webhook-shared-secret"
)
```
