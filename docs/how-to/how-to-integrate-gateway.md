# How to Route LLM Requests Through AI Gateway

Hướng dẫn cấu hình ứng dụng để định tuyến các lệnh gọi OpenAI / LLM qua AI Gateway nhằm tự động lọc PII, chặn Shadow AI và lưu vết kiểm toán bất biến.

---

## Prerequisites (Yêu cầu Trước khi Thực hiện)
- Dịch vụ AI Gateway đang chạy tại `http://localhost:8081`.
- Đã đăng ký mã hệ thống trong tệp `configs/registry.json` (ví dụ: `customer-assistant-llm` hoặc `credit-scoring-ml`).

---

## Steps (Các Bước Thực hiện)

### Bước 1: Trỏ Base URL trong OpenAI SDK về Gateway
Thay vì gọi trực tiếp tới `https://api.openai.com/v1`, chuyển hướng `base_url` sang cổng của AI Gateway:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8081/v1",
    api_key="your-api-key",  # Gateway sẽ chuyển tiếp nguyên vẹn tới LLM upstream
    default_headers={
        "X-AI-System-ID": "customer-assistant-llm",  # BẮT BUỘC: Đăng ký AI Registry
        "X-Correlation-ID": "order-req-20261006-001", # Khuyến nghị: Mã vết giao dịch
    }
)
```

### Bước 2: Gửi Lệnh gọi Chat Completion có PII
Gửi tin nhắn chứa thông tin nhạy cảm của khách hàng Việt Nam (CCCD, SĐT, STK):

```python
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "Bạn là nhân viên hỗ trợ khách hàng."},
        {"role": "user", "content": "Khách hàng Nguyễn Văn A, CCCD: 001234567890, SĐT: 0987654321, STK: 190345678912 muốn tra cứu dư nợ."}
    ],
    stream=True # Hỗ trợ SSE streaming pass-through tức thì
)

# Đọc token theo luồng
for chunk in response:
    content = chunk.choices[0].delta.content or ""
    print(content, end="", flush=True)
print()
```

### Bước 3: Kích hoạt Chế độ Phê duyệt Chặn dòng (Intercept & Approve)
Khi cần sự phê duyệt của con người đối với các quyết định rủi ro cao, thêm header `X-Require-Approval: true` hoặc tham số `extra_body={"requires_approval": True}`:

```python
import requests

payload = {
    "model": "gpt-4o",
    "messages": [
        {"role": "user", "content": "Phê duyệt giải ngân khoản vay 500 triệu đồng cho khách hàng CCCD 001234567890."}
    ],
    "requires_approval": True
}

headers = {
    "Content-Type": "application/json",
    "X-AI-System-ID": "credit-scoring-ml",
    "X-Require-Approval": "true"
}

res = requests.post("http://localhost:8081/v1/chat/completions", json=payload, headers=headers)
print("HTTP Status:", res.status_code) # 202 Accepted
print("Phản hồi:", res.json())
```
*Kết quả nhận được:*
```json
{
  "status": "PENDING_APPROVAL",
  "decision_id": "dec-llm-123e4567-e89b-12d3-a456-426614174000",
  "poll_url": "/api/v1/decisions/dec-llm-123e4567-e89b-12d3-a456-426614174000/status"
}
```

---

## Verification (Kiểm tra & Xác minh)

1. **Kiểm tra Lọc PII trong Sổ cái**:
   - Dữ liệu gửi đến LLM upstream được lọc và che theo đúng cấu hình.
   - Bản ghi kiểm toán lưu trong immudb chứa trường `input_masked` với CCCD và SĐT đã được thay bằng `************` và `**********`.
2. **Kiểm tra Chặn Shadow AI**:
   - Gửi yêu cầu với header `X-AI-System-ID: unknown-bot`:
   ```bash
   curl -X POST http://localhost:8081/v1/chat/completions \
     -H "Content-Type: application/json" \
     -H "X-AI-System-ID: unknown-bot" \
     -d "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"Hi\"}]}"
   ```
   *Kết quả phải trả về ngay lập tức `HTTP 403 Forbidden` kèm lỗi `System ID 'unknown-bot' not registered in AI Registry`.*

---

## Troubleshooting (Xử lý Sự cố Thường gặp)

### 1. Lỗi HTTP 403 Forbidden
- **Nguyên nhân**: Quên truyền header `X-AI-System-ID`, hoặc `system_id` chưa được định nghĩa trong `configs/registry.json`.
- **Khắc phục**: Mở `configs/registry.json`, thêm cấu hình hệ thống AI của bạn vào danh sách `systems`, sau đó khởi động lại Gateway.

### 2. Lỗi HTTP 502 Bad Gateway
- **Nguyên nhân**: LLM upstream (`UPSTREAM_URL`) bị tắt, cấu hình sai cổng, hoặc mạng chập chờn.
- **Khắc phục**: Kiểm tra trạng thái của Mock LLM (`http://localhost:8080/health`) hoặc máy chủ vLLM/Ollama của doanh nghiệp.
