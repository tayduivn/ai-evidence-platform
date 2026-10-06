# How to Integrate Client SDKs (Python & Enterprise Java)

Hướng dẫn tích hợp bộ thư viện Client SDK vào ứng dụng máy học (Python) và hệ thống Core backend (Java) để ghi nhận quyết định và xử lý quy trình phê duyệt người kiểm soát.

---

## Phần 1: Tích hợp Python SDK (`ai_evidence_sdk`)

### Prerequisites
- Python 3.9 trở lên.
- Cài đặt SDK từ mã nguồn cục bộ:
  ```bash
  cd sdks/python
  pip install -e .
  ```

### Các Bước Thực hiện (Python)

#### Bước 1: Khởi tạo Client
```python
from ai_evidence_sdk import EvidenceClient, DropPolicy

client = EvidenceClient(
    ingest_url="http://localhost:8081/api/v1/ml/ingest",
    max_queue_size=10000,
    drop_policy=DropPolicy.DROP_OLDEST, # Xóa cũ nạp mới khi đầy đệm
    auto_flush_on_exit=True
)
```

#### Bước 2: Ghi Nhật ký Quyết định Non-Blocking (< 5ms SLA)
Gọi hàm `log_decision()` trực tiếp trong luồng tính toán của model:

```python
import time

event = {
    "decision_id": "dec-credit-9921",
    "correlation_id": "tx-app-20261006-01",
    "ai_system_id": "credit-scoring-ml",
    "model_version": "v2.1.0",
    "features": {
        "income": 20000000,
        "debt_ratio": 0.25,
        "phone": "0912345678"
    },
    "score": 0.88,
    "decision": "APPROVE",
    "explanation": {"income_weight": 0.6}
}

t0 = time.perf_counter()
success = client.log_decision(event)
elapsed_ms = (time.perf_counter() - t0) * 1000

print(f"Ghi log thành công: {success} (Độ trễ: {elapsed_ms:.4f} ms)")
# Luôn trả về < 5.0ms (thực tế ~ 0.03ms), không làm chậm ứng dụng
```

#### Bước 3: Gửi Quyết định Yêu cầu Phê duyệt
Khi quyết định thuộc diện rủi ro cao:

```python
handle = client.request_approval(
    event,
    creator_id="underwriter_app",
    timeout=10.0
)

print("Đã tạo yêu cầu duyệt. Mã quyết định:", handle.decision_id)
print("Theo dõi tại:", handle.poll_url)

# Chờ kết quả duyệt từ con người (đồng bộ hoặc bất đồng bộ)
result = handle.wait_for_approval(timeout=120.0, poll_interval=2.0)
if result.is_approved:
    print("Khoản vay ĐÃ ĐƯỢC DUYỆT bởi:", result.approvers)
    print("Chữ ký số hợp lệ:", result.signature[:30], "...")
else:
    print("Khoản vay BỊ TỪ CHỐI:", result.status)
```

---

## Phần 2: Tích hợp Enterprise Java SDK (`com.aievidence.sdk`)

### Prerequisites
- JDK 17 LTS trở lên.
- Maven hoặc Gradle.

### Các Bước Thực hiện (Java)

#### Bước 1: Khởi tạo Client trong Spring Boot hoặc Java Service
```java
import com.aievidence.sdk.EvidenceClient;
import com.aievidence.sdk.ClientConfig;
import com.aievidence.sdk.model.DropPolicy;
import com.aievidence.sdk.model.DecisionEvent;

ClientConfig config = ClientConfig.builder()
    .ingestUrl("http://localhost:8081/api/v1/ml/ingest")
    .queueCapacity(50000)
    .dropPolicy(DropPolicy.DROP_OLDEST)
    .build();

EvidenceClient client = EvidenceClient.create(config);
```

#### Bước 2: Ghi Log Quyết định Siêu Tốc
```java
DecisionEvent event = DecisionEvent.builder()
    .decisionId("dec-fraud-9812")
    .correlationId("tx-core-1102")
    .aiSystemId("fraud-detector-v2")
    .modelVersion("v2.4.1")
    .feature("amount", 150000000)
    .feature("recipient_bank", "970422")
    .score(0.95)
    .decision("BLOCK")
    .build();

// Non-blocking enqueue chỉ mất 0.0021ms
boolean accepted = client.logDecision(event);
```

#### Bước 3: Xử lý Phê duyệt Bất đồng bộ với CompletableFuture
```java
import java.time.Duration;

client.requestApprovalAsync(event, Duration.ofSeconds(60))
    .thenAccept(result -> {
        if (result.isApproved()) {
            System.out.println("Giao dịch được mở khóa bởi: " + result.getApprovers());
        } else {
            System.out.println("Giao dịch bị chặn: " + result.getStatus());
        }
    })
    .exceptionally(ex -> {
        System.err.println("Lỗi xử lý duyệt: " + ex.getMessage());
        return null;
    });
```

---

## Verification (Kiểm tra Tính Độc lập & Cách ly Lỗi)

Thực hiện kiểm tra tính chất **Zero Exception Leakage**:
1. Tạm dừng Ingest API hoặc cấu hình `ingest_url` trỏ vào một cổng không tồn tại (ví dụ: `http://127.0.0.1:59999`).
2. Chạy hàm `log_decision()`:
   ```python
   # Chạy 1,000 lần liên tục
   for i in range(1000):
       client.log_decision({"decision_id": f"test-{i}", "score": 0.5})
   ```
3. **Kết quả xác nhận**:
   - Ứng dụng không bao giờ bị ném `ConnectionRefusedError` hoặc crash.
   - Hàm luôn hoàn thành trong < 5ms.
   - Worker nền tự động thử lại với thuật toán exponential backoff cho đến khi server online trở lại.
