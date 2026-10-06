# Resilience & Non-Blocking Design: Guaranteeing Zero Caller Failures

Tài liệu giải thích nguyên lý thiết kế độ bền vững (Resilience), cơ chế đệm cục bộ không chặn luồng (Non-blocking In-Memory Buffers), và thuật toán tự phục hồi lỗi đĩa cứng (DiskWAL Crash Recovery).

---

## 1. Nguyên tắc Bất biến: Ứng dụng AI Không Bao giờ Sập vì Ghi Log

Trong các hệ thống AI phục vụ nghiệp vụ thời gian thực (Real-time AI Inference):
- Mô hình chấm điểm gian lận thẻ tín dụng phải phản hồi cho ngân hàng trong vòng **< 100ms**.
- Nếu SDK ghi log kiểm toán gọi trực tiếp HTTP sang Ingest API qua mạng một cách đồng bộ:
  - Khi Ingest API bị trễ mạng hoặc restart, luồng nghiệp vụ của ngân hàng sẽ bị treo, dẫn đến timeout giao dịch của khách hàng.
  - Tệ hơn, nếu Ingest API bị sập, ngoại lệ (exception) mạng sẽ bắn thẳng ra ứng dụng gọi nếu không được cô lập, làm sập toàn bộ dịch vụ thanh toán.

**Nguyên lý Thiết kế của Nền tảng**:
> *"Việc ghi vết kiểm toán là tối quan trọng, nhưng KHÔNG BAO GIỜ được phép làm sập hoặc chặn đứng luồng nghiệp vụ chính của ứng dụng AI."*

---

## 2. Kiến trúc Bộ đệm Vòng Bị chặn (Bounded Ring Buffer) trong SDKs

Cả Python SDK và Java SDK đều áp dụng mô hình **Producer - Consumer** phân tách hoàn toàn giữa luồng nghiệp vụ và luồng truyền thông mạng:

```text
Luồng Nghiệp vụ (ML Thread)
       │
       ▼ (1) Enqueue < 0.05ms (SLA < 5.0ms)
┌───────────────────────────────────────────────┐
│     Bộ đệm Vòng Bounded In-Memory Queue       │
│     (Python: collections.deque /              │
│      Java: ArrayBlockingQueue)                │
└──────────────────────┬────────────────────────┘
                       │
                       ▼ (2) Worker nền đọc micro-batch
               Delivery Worker Thread
                       │
                       ▼ (3) Gửi HTTP Keep-Alive
              AI Gateway / Ingest API
```

### 2.1. Đảm bảo SLA Độ trễ Enqueue < 5.0ms
- Khi gọi `log_decision()`, SDK chỉ thực hiện một thao tác ghi nhớ duy nhất: đẩy phần tử vào hàng đợi bộ nhớ.
- Thao tác này hoàn thành trong **0.026ms (Python)** và **0.0021ms (Java)**, vượt xa cam kết SLA (< 5.0ms).
- Luồng nghiệp vụ nhận về `True` và tiếp tục tính toán mà không phải chờ I/O mạng.

### 2.2. Chính sách Xử lý khi Đệm Bị Tràn (`DropPolicy`)
Nếu Ingest API bị mất kết nối kéo dài hàng giờ và hàng đợi bộ đệm đạt sức chứa tối đa (ví dụ 10,000 sự kiện):
1. **`DROP_OLDEST` (Mặc định)**:
   - Tự động đẩy phần tử cũ nhất ra khỏi hàng đợi để nhường chỗ cho sự kiện mới nhất.
   - Thích hợp cho các hệ thống giám sát và vận hành: dữ liệu thời gian thực gần nhất luôn được bảo toàn.
2. **`DROP_NEWEST`**:
   - Từ chối tiếp nhận sự kiện mới để giữ nguyên vẹn chuỗi sự kiện lịch sử đã xếp hàng trước đó.
   - Hàm `log_decision()` trả về `False` trong thời gian ngắn mà không ném lỗi ra ngoài.

---

## 3. Khôi phục Sự cố trên Máy chủ với DiskWAL (Write-Ahead Log)

Khi sự kiện đã rời SDK và đến được máy chủ Ledger Worker (`services/ledger/`):
- **Vấn đề**: Nếu máy chủ Ledger nhận sự kiện nhưng bị cúp điện đột ngột trước khi kịp ghi vào immudb, dữ liệu trong RAM sẽ bị mất.
- **Giải pháp DiskWAL**:
  1. Sự kiện vừa vào worker sẽ được đóng gói dạng khung nhị phân (`walMagic = 0x57414C31`) có gắn mã kiểm tra lỗi **CRC32** và ghi ngay lập tức xuống tệp phân đoạn ổ đĩa (`wal-00000001.log`).
  2. Các tệp WAL tự động xoay vòng (rotate) khi kích thước đạt 10MB.
  3. **Thuật toán Khôi phục khi Khởi động lại (Crash Recovery)**:
     - Khi Ledger Worker khởi động lại sau crash, hàm `ReplayPending()` quét toàn bộ thư mục `/var/lib/ledger/wal`.
     - Nhận diện tệp segment cuối cùng có dữ liệu chưa ghi, niêm phong lại thành phân đoạn lịch sử và tăng sequence number.
     - Đọc tuần tự, kiểm tra tính toàn vẹn CRC32 của từng frame, và đẩy lại toàn bộ các sự kiện tồn đọng vào immudb trước khi bắt đầu nhận sự kiện mới.

---

## 4. Tối ưu Kết nối & Chống Socket Churn trên Windows / Linux

Trong các bài kiểm tra tải nặng (Benchmark 120 calls với 74.5KB payload):
- Việc mở và đóng kết nối HTTP mới cho mỗi request trên localhost Windows sẽ gây ra hiện tượng cạn kiệt socket (`TIME_WAIT` socket churn), làm độ trễ p95 tăng ảo lên 30ms - 50ms.
- **Giải pháp**: Tất cả các thành phần (Gateway, SDK, Benchmark runner) đều sử dụng **HTTP Connection Pooling** với Keep-Alive (`requests.Session` có `HTTPAdapter(pool_connections=10, pool_maxsize=10)` trong Python và `HttpClient` kết nối tái sử dụng trong Go/Java).
- Kết quả: Độ trễ gia tăng p95 của Gateway đo được ổn định ở mức **6.54ms – 8.54ms**, hoàn toàn vượt chuẩn cam kết (< 15.0ms).
