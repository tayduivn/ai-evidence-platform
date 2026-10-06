# Configuration Reference: AI Evidence Platform

Tài liệu tham chiếu toàn bộ biến môi trường (Environment Variables) và tệp cấu hình của hệ thống.

---

## 1. Cấu hình Cụm Dịch vụ Docker Compose (`.env` / `docker-compose.yml`)

### 1.1. AI Gateway (`services/gateway/`)
Cổng mặc định: `8081`

| Biến môi trường | Kiểu dữ liệu | Giá trị mặc định | Mô tả |
|---|---|---|---|
| `PORT` | Số nguyên | `8081` | Cổng HTTP mà AI Gateway lắng nghe. |
| `UPSTREAM_URL` | URL | `http://mock-llm:8080` | URL máy chủ LLM upstream (OpenAI API hoặc vLLM/Ollama). |
| `REGISTRY_CONFIG_PATH` | Đường dẫn | `configs/registry.json` | Đường dẫn tới tệp định danh các hệ thống AI hợp lệ. |
| `LEDGER_INGEST_URL` | URL | `http://ledger-worker:8083/api/v1/events` | Endpoint đẩy sự kiện kiểm toán sang Ledger Worker. |
| `PII_MASK_CHAR` | Ký tự | `*` | Ký tự dùng để che các trường PII nhạy cảm. |
| `HTTP_TIMEOUT_SECONDS` | Số nguyên | `60` | Thời gian timeout khi gửi yêu cầu tới LLM Upstream. |

---

### 1.2. Ledger Worker & Storage (`services/ledger/`)
Cổng mặc định: `8083`

| Biến môi trường | Kiểu dữ liệu | Giá trị mặc định | Mô tả |
|---|---|---|---|
| `PORT` | Số nguyên | `8083` | Cổng HTTP cho worker và healthcheck. |
| `IMMUDB_ADDRESS` | Hostname/IP | `immudb` | Địa chỉ máy chủ cơ sở dữ liệu sổ cái bất biến immudb. |
| `IMMUDB_PORT` | Số nguyên | `3324` | Cổng giao tiếp REST/Web của immudb (hoặc `3322` gRPC). |
| `IMMUDB_DATABASE` | Chuỗi | `defaultdb` | Tên cơ sở dữ liệu trong immudb. |
| `IMMUDB_USERNAME` | Chuỗi | `immudb` | Tài khoản đăng nhập immudb. |
| `IMMUDB_PASSWORD` | Chuỗi | `immudb` | Mật khẩu tài khoản immudb (cần bảo mật ở production). |
| `LEDGER_QUEUE_CAPACITY`| Số nguyên | `50000` | Kích thước hàng đợi sự kiện bộ nhớ trước khi ghi. |
| `LEDGER_BATCH_SIZE` | Số nguyên | `100` | Số lượng sự kiện gom trong một micro-batch. |
| `LEDGER_FLUSH_INTERVAL_MS`| Số nguyên | `50` | Chu kỳ tối đa để ghi batch xuống immudb (mili-giây). |
| `WAL_DIR` | Đường dẫn | `/var/lib/ledger/wal` | Thư mục lưu trữ các tệp phân đoạn DiskWAL dự phòng. |
| `ANCHOR_INTERVAL_SEC` | Số nguyên | `3600` | Chu kỳ gửi yêu cầu đóng dấu thời gian RFC 3161 ra bên ngoài. |
| `TSA_SERVER_URL` | URL | `http://tsa.example.com` | Địa chỉ máy chủ Timestamp Authority độc lập. |

---

### 1.3. Human-in-the-Loop Approval Service (`services/approval/`)
Cổng mặc định: `8082`

| Biến môi trường | Kiểu dữ liệu | Giá trị mặc định | Mô tả |
|---|---|---|---|
| `PORT` | Số nguyên | `8082` | Cổng phục vụ Web UI và REST API phê duyệt. |
| `STORAGE_DIR` | Đường dẫn | `/var/lib/approval/data`| Thư mục lưu trữ trạng thái máy phê duyệt. |
| `MIN_DWELL_SECONDS` | Số nguyên | `10` | Ngưỡng thời gian đọc tài liệu tối thiểu chống duyệt bừa. |
| `SIGNER_TYPE` | Chuỗi | `internal` | Cơ chế ký số: `internal`, `ca_vn_token`, hoặc `ca_vn_remote`. |
| `SIGNER_PRIVATE_KEY_PATH`| Đường dẫn | `certs/internal_signer.key` | Khóa riêng RSA/ECDSA dùng cho cơ chế Internal Signer. |
| `SIGNER_CERT_PATH` | Đường dẫn | `certs/internal_signer.pem` | Chứng thư số tương ứng với khóa riêng. |
| `CA_VN_TOKEN_PIN` | Chuỗi | `""` | Mã PIN mở khóa thiết bị USB Token phần cứng. |
| `CA_VN_REMOTE_API_URL`| URL | `""` | Địa chỉ Gateway ký số từ xa theo chuẩn Cloud Signature Consortium. |

---

## 2. Cấu hình AI Registry (`registry.json`)

Tệp `registry.json` xác định danh mục các mô hình AI và ứng dụng được phép hoạt động qua Gateway:

```json
{
  "systems": [
    {
      "system_id": "credit-scoring-ml",
      "name": "Mô hình Chấm điểm Tín dụng Bán lẻ",
      "model_type": "xgboost",
      "version": "v2.1.0",
      "requires_approval": true,
      "allowed_users": ["credit-worker-01", "mobile-app-be"]
    },
    {
      "system_id": "customer-assistant-llm",
      "name": "Chatbot Hỗ trợ Khách hàng 24/7",
      "model_type": "gpt-4o",
      "version": "latest",
      "requires_approval": false,
      "prompt_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

- Nếu `requires_approval: true`: Gateway tự động kích hoạt chế độ **Intercept & Approve (HTTP 202)** cho mọi yêu cầu thuộc hệ thống này.
- Nếu `prompt_hash` được thiết lập: Gateway sẽ từ chối nếu request có prompt hệ thống không khớp với hash SHA-256 đã đăng ký.
