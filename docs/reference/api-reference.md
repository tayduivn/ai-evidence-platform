# API Reference: AI Evidence & Accountability Platform

Tài liệu tham chiếu chi tiết các endpoint HTTP REST API của AI Gateway (`:8081`), Human-in-the-Loop Approval Service (`:8082`), và Micro-batching Ledger Worker (`:8083`).

> [!TIP]
> Bạn có thể tải tệp đặc tả kỹ thuật máy tính đọc được tại [OpenAPI 3.0 Spec (openapi.yaml)](openapi.yaml) để import trực tiếp vào Swagger UI, Postman, hoặc dùng cho các công cụ tự động sinh mã nguồn (SDK Generators).

---

## 1. AI Gateway API (`:8081`)

### 1.1. Reverse Proxy Chat Completions
Chuyển tiếp yêu cầu suy luận tới LLM Upstream, đồng thời thực hiện kiểm soát Shadow AI, lọc PII, và ghi nhật ký kiểm toán.

- **Endpoint**: `POST /v1/chat/completions` (hoặc `POST /chat/completions`)
- **Headers bắt buộc**:
  - `Content-Type: application/json`
  - `X-AI-System-ID: <system-id>` (Mã hệ thống đã đăng ký trong AI Registry)
- **Headers tùy chọn**:
  - `X-AI-Prompt-Hash: <sha256-hash>` (Kiểm tra toàn vẹn prompt hệ thống)
  - `X-Require-Approval: true | false` (Ghi đè chế độ Intercept 202)
  - `X-Correlation-ID: <uuid>` (Mã vết luồng nghiệp vụ)
  - `Authorization: Bearer <token>` (Chuyển tiếp nguyên vẹn tới LLM upstream)

#### Request Body
Tuân thủ định dạng chuẩn OpenAI Chat Completion:
```json
{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "Bạn là trợ lý tín dụng."},
    {"role": "user", "content": "Khách hàng Nguyễn Văn A, CCCD 001234567890 yêu cầu vay."}
  ],
  "stream": true,
  "requires_approval": false
}
```

#### Response (Audit-Only Mode, Non-Streaming)
- **Status Code**: `200 OK`
- **Body**: Phản hồi trực tiếp từ LLM Upstream (kèm theo PII đã được che trong sổ cái kiểm toán).

#### Response (Audit-Only Mode, SSE Streaming)
- **Status Code**: `200 OK`
- **Content-Type**: `text/event-stream`
- **Body**: Chuỗi sự kiện `data: {...}\n\n` kèm token hoàn tất `data: [DONE]\n\n`.

#### Response (Intercept & Approve Mode)
- **Status Code**: `202 Accepted`
- **Headers**: `Location: /api/v1/decisions/<decision_id>/status`
- **Body**:
```json
{
  "status": "PENDING_APPROVAL",
  "decision_id": "dec-llm-123e4567-e89b-12d3-a456-426614174000",
  "correlation_id": "tx-987e6543-e21b-12d3-a456-426614174000",
  "poll_url": "/api/v1/decisions/dec-llm-123e4567-e89b-12d3-a456-426614174000/status"
}
```

#### Error Codes
- `400 Bad Request`: JSON body không hợp lệ hoặc thiếu trường bắt buộc.
- `403 Forbidden`: `X-AI-System-ID` không tồn tại trong Registry (Shadow AI) hoặc hash không khớp.
- `502 Bad Gateway`: LLM Upstream bị sập hoặc ngắt kết nối đột ngột.
- `504 Gateway Timeout`: LLM Upstream phản hồi vượt quá thời gian timeout (mặc định 60s).

---

### 1.2. Thăm dò Trạng thái Quyết định (Decision Status Polling)
Kiểm tra trạng thái của quyết định bị tạm giữ để phê duyệt.

- **Endpoint**: `GET /api/v1/decisions/{id}/status`
- **Parameters**: `id` (Decision ID)

#### Response (`PENDING`)
- **Status Code**: `200 OK`
```json
{
  "decision_id": "dec-llm-123e4567-e89b-12d3-a456-426614174000",
  "status": "PENDING",
  "is_terminal": false,
  "created_at": "2026-10-06T03:00:00Z"
}
```

#### Response (`APPROVED`)
- **Status Code**: `200 OK`
```json
{
  "decision_id": "dec-llm-123e4567-e89b-12d3-a456-426614174000",
  "status": "APPROVED",
  "is_terminal": true,
  "approvers": ["auditor_1@corp.vn", "manager_2@corp.vn"],
  "signature": "3045022100...",
  "updated_at": "2026-10-06T03:02:15Z"
}
```

---

### 1.3. ML Ingest API
Tiếp nhận sự kiện quyết định từ các pipeline Machine Learning (Fraud Detection, Credit Scoring, Recommendation).

- **Endpoint**: `POST /api/v1/ml/ingest`
- **Headers bắt buộc**:
  - `Content-Type: application/json`
  - `X-AI-System-ID: <system-id>`

#### Request Body
```json
{
  "decision_id": "dec-ml-88371923",
  "correlation_id": "tx-core-9912",
  "model_version": "v2.1.0",
  "features": {
    "income": 25000000,
    "debt_ratio": 0.28,
    "phone": "0912345678",
    "cccd": "001234567890"
  },
  "score": 0.89,
  "decision": "APPROVE",
  "explanation": {
    "income_contribution": 0.45,
    "debt_contribution": -0.12
  },
  "requires_approval": false,
  "creator_id": "pipeline-worker-01"
}
```

#### Response
- **Status Code**: `200 OK` (Khi `requires_approval=false`)
```json
{
  "status": "ENQUEUED",
  "decision_id": "dec-ml-88371923",
  "correlation_id": "tx-core-9912"
}
```
- **Status Code**: `202 Accepted` (Khi `requires_approval=true`)
```json
{
  "status": "PENDING_APPROVAL",
  "decision_id": "dec-ml-88371923",
  "poll_url": "/api/v1/decisions/dec-ml-88371923/status"
}
```

---

## 2. Human-in-the-Loop Approval Service API (`:8082`)

### 2.1. Danh sách Quyết định Chờ Duyệt
- **Endpoint**: `GET /api/v1/approvals/pending`
- **Query Params**: `limit=50&offset=0`
- **Response**:
```json
{
  "total": 3,
  "items": [
    {
      "decision_id": "dec-ml-88371923",
      "ai_system_id": "credit-scoring-ml",
      "status": "PENDING",
      "created_at": "2026-10-06T03:10:00Z",
      "min_dwell_ms": 3000
    }
  ]
}
```

### 2.2. Chi tiết Quyết định & Heartbeat Thời gian Đọc (Dwell Time)
- **Lấy chi tiết**: `GET /api/v1/approvals/{id}`
- **Gửi Heartbeat Dwell Time**: `POST /api/v1/approvals/{id}/dwell`
  - **Body**:
    ```json
    {
      "session_token": "sess-token-xyz-123",
      "elapsed_ms": 3500
    }
    ```
  - **Response**: `{"status": "OK", "recorded_ms": 3500, "eligible": true}`

### 2.3. Thực hiện Phê duyệt / Từ chối (Submit Decision Action)
- **Endpoint**: `POST /api/v1/approvals/{id}/decide`
- **Headers**:
  - `Content-Type: application/json`
  - `X-Approver-ID: <email-or-username>`
- **Request Body**:
```json
{
  "action": "APPROVE",
  "comment": "Đã đối chiếu thông tin thu nhập qua sao kê.",
  "session_token": "sess-token-xyz-123",
  "signer_type": "internal"
}
```
- **Giá trị `action` hợp lệ**: `APPROVE`, `REJECT`.
- **Giá trị `signer_type` hợp lệ**: `internal`, `ca_vn_token`, `ca_vn_remote`.

#### Response (Bước 1 của Quy tắc 4-mắt)
- **Status Code**: `200 OK`
```json
{
  "decision_id": "dec-ml-88371923",
  "status": "APPROVED_1",
  "message": "First approval recorded. Waiting for second approver.",
  "approver_1": "auditor_1@corp.vn"
}
```

#### Response (Bước 2 - Phê duyệt Hoàn tất & Ký số)
- **Status Code**: `200 OK`
```json
{
  "decision_id": "dec-ml-88371923",
  "status": "APPROVED_FINAL",
  "approver_1": "auditor_1@corp.vn",
  "approver_2": "manager_2@corp.vn",
  "signature": "3045022100d3...",
  "signed_at": "2026-10-06T03:15:20Z"
}
```

#### Lỗi thường gặp
- `400 Bad Request`: `Self-approval rejected` (Người tạo tự duyệt) hoặc `Insufficient dwell time` (Thời gian đọc chưa đủ).
- `409 Conflict`: Quyết định đã ở trạng thái kết thúc (Terminal state) hoặc đã được duyệt bởi cùng một người ở bước 1.

---

## 3. Health & Monitoring Probes (All Services)

| Dịch vụ | Liveness Probe | Readiness Probe |
|---|---|---|
| Gateway (`:8081`) | `GET /health` | `GET /ready` |
| Approval Service (`:8082`) | `GET /health` | `GET /ready` |
| Ledger Worker (`:8083`) | `GET /health` | `GET /ready` |
| Mock LLM (`:8080`) | `GET /health` | N/A |
