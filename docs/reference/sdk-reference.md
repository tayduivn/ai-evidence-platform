# SDK Reference: Python & Enterprise Java

Tài liệu tham chiếu chi tiết bộ thư viện Client SDK dành cho việc tích hợp ghi nhật ký quyết định và luồng phê duyệt người kiểm soát (Human-in-the-loop).

---

## 1. Python SDK (`ai_evidence_sdk`)

Bộ công cụ Client cho Python được tối ưu hóa cho các dịch vụ mô hình Machine Learning, bảo đảm không bao giờ làm nghẽn hoặc sập luồng nghiệp vụ khi ghi dữ liệu kiểm toán.

### 1.1. Lớp `EvidenceClient`

#### Constructor
```python
from ai_evidence_sdk import EvidenceClient, ClientConfig, DropPolicy

client = EvidenceClient(
    ingest_url="http://localhost:8081/api/v1/ml/ingest",
    max_queue_size=10000,
    drop_policy=DropPolicy.DROP_OLDEST,
    config=None,
    **kwargs
)
```

**Các tham số chính:**
- `ingest_url` (*str*): URL của Gateway hoặc ML Ingest API (mặc định: `http://localhost:8081/api/v1/ml/ingest`).
- `max_queue_size` (*int*): Sức chứa tối đa của hàng đợi vòng trong bộ nhớ (mặc định: `10000`).
- `drop_policy` (*DropPolicy*): Chính sách xử lý khi hàng đợi đầy:
  - `DropPolicy.DROP_OLDEST`: Loại bỏ sự kiện cũ nhất để nạp sự kiện mới (khuyến nghị cho hệ thống đo lường).
  - `DropPolicy.DROP_NEWEST`: Từ chối sự kiện mới nhất để bảo toàn chuỗi sự kiện cũ.
- `auto_flush_on_exit` (*bool*): Tự động giải phóng và gửi toàn bộ sự kiện khi tiến trình Python kết thúc qua hook `atexit` (mặc định: `True`).

---

#### Phương thức `log_decision()`
Ghi lại quyết định của mô hình AI/ML vào sổ cái kiểm toán bất biến.

```python
success: bool = client.log_decision(event_data)
```

- **Đầu vào `event_data`**: Có thể là `dict` hoặc đối tượng `MLDecisionEvent`.
- **Cam kết SLA**: Hoàn thành trong thời gian **< 5.0ms** (thực tế đo được: **0.026ms**).
- **Cách ly sự cố**: Không bao giờ ném ngoại lệ (Zero Exception Leakage). Nếu hàng đợi đầy (dưới chính sách `DROP_NEWEST`) hoặc client đã đóng, hàm trả về `False`.
- **Giá trị trả về**: `True` nếu sự kiện được chấp nhận vào hàng đợi; `False` nếu bị từ chối.

---

#### Phương thức `request_approval()`
Gửi yêu cầu phê duyệt cho các quyết định rủi ro cao hoặc vượt hạn mức thẩm quyền.

```python
handle: ApprovalHandle = client.request_approval(
    event_data,
    webhook_url=None,
    creator_id=None,
    timeout=10.0,
    pre_validate_pii=False,
    pii_mode="warn"
)
```

- **Tham số:**
  - `event_data` (*dict* hoặc *MLDecisionEvent*): Dữ liệu quyết định.
  - `webhook_url` (*str*, tùy chọn): Endpoint nhận callback khi phê duyệt hoàn tất.
  - `creator_id` (*str*, tùy chọn): Mã định danh người tạo (phục vụ ràng buộc quy tắc 4-mắt).
  - `pre_validate_pii` (*bool*): Kích hoạt quét PII cục bộ trước khi gửi lên mạng.
  - `pii_mode` (*str*): `"warn"` (cảnh báo vào log), `"mask"` (tự che PII trước khi gửi), hoặc `"block"` (ném `PIIValidationError`).
- **Giá trị trả về `ApprovalHandle`**:
  - `handle.decision_id`: Mã quyết định.
  - `handle.poll_url`: Đường dẫn kiểm tra trạng thái.
  - `handle.wait_for_approval(timeout=60.0, poll_interval=1.0) -> ApprovalResult`: Khối lệnh đồng bộ chờ kết quả duyệt từ con người.

---

### 1.2. Lớp `MLDecisionEvent`
Data model có cấu trúc đại diện cho một quyết định máy học.

```python
from ai_evidence_sdk import MLDecisionEvent

event = MLDecisionEvent(
    decision_id="dec-fraud-001",
    correlation_id="tx-order-9988",
    ai_system_id="fraud-detector-v2",
    model_version="2.4.1",
    features={"amount": 50000000, "ip": "14.162.x.x"},
    score=0.92,
    decision="BLOCK",
    explanation={"risk_factor": "unusual_velocity"}
)
```

---

## 2. Enterprise Java SDK (`com.aievidence.sdk`)

Xây dựng trên nền tảng **Java 17 LTS**, không phụ thuộc bất kỳ thư viện bên ngoài nào (zero 3rd-party dependencies), tối ưu cho các hệ thống Core Banking, Fintech và Viễn thông.

### 2.1. Lớp `EvidenceClient`

#### Khởi tạo qua Builder
```java
import com.aievidence.sdk.EvidenceClient;
import com.aievidence.sdk.ClientConfig;
import com.aievidence.sdk.model.DropPolicy;

ClientConfig config = ClientConfig.builder()
    .ingestUrl("http://localhost:8081/api/v1/ml/ingest")
    .queueCapacity(50000)
    .dropPolicy(DropPolicy.DROP_OLDEST)
    .httpTimeoutMs(5000)
    .batchSize(100)
    .flushIntervalMs(50)
    .build();

EvidenceClient client = EvidenceClient.create(config);
```

---

#### Phương thức `logDecision(DecisionEvent event)`
- **Đặc tính**: Non-blocking in-memory enqueue. Đẩy vào hàng đợi `ArrayBlockingQueue` trong vòng **0.0021ms**.
- **An toàn luồng**: Thread-safe tuyệt đối, hỗ trợ hàng triệu giao dịch mỗi giây.
- **Xử lý lỗi**: Bắt toàn bộ `Throwable`, trả về `false` nếu hàng đợi đầy hoặc client đã đóng. Không làm gián đoạn luồng nghiệp vụ.

```java
DecisionEvent event = DecisionEvent.builder()
    .decisionId("dec-loan-7712")
    .correlationId("tx-app-4412")
    .aiSystemId("underwriting-engine")
    .modelVersion("1.0.4")
    .feature("income", 30000000)
    .feature("credit_score", 720)
    .score(0.85)
    .decision("APPROVE")
    .build();

boolean enqueued = client.logDecision(event);
```

---

#### Phương thức `requestApprovalAsync(DecisionEvent event, Duration timeout)`
Gửi quyết định cần kiểm duyệt và nhận về `CompletableFuture<ApprovalResult>`.

```java
CompletableFuture<ApprovalResult> future = client.requestApprovalAsync(event, Duration.ofSeconds(30));

future.thenAccept(result -> {
    if (result.isApproved()) {
        System.out.println("Quyết định được phê duyệt bởi: " + result.getApprovers());
        System.out.println("Chữ ký điện tử: " + result.getSignatureHex());
    } else {
        System.out.println("Quyết định bị từ chối: " + result.getStatus());
    }
});
```

---

### 2.2. Quản lý Tài nguyên với `AutoCloseable`
`EvidenceClient` tự động triển khai `AutoCloseable`. Khi sử dụng trong khối `try-with-resources`, client sẽ tự động flush toàn bộ sự kiện còn tồn đọng trong bộ đệm sang Worker trước khi giải phóng luồng:

```java
try (EvidenceClient client = EvidenceClient.create(config)) {
    client.logDecision(event);
} // Tự động đóng worker và giải phóng thread pool an toàn
```
