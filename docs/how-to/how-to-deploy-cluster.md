# How to Deploy the AI Evidence Platform Cluster

Hướng dẫn triển khai cụm 5 container của nền tảng AI Evidence Platform bằng Docker Compose và kiểm tra trạng thái hoạt động của toàn bộ dịch vụ.

---

## Prerequisites (Yêu cầu Trước khi Cài đặt)
- Đã cài đặt **Docker Desktop** (trên Windows / macOS) hoặc **Docker Engine** và **Docker Compose v2** (trên Linux).
- Tối thiểu 4GB RAM trống và 10GB dung lượng đĩa cứng.
- Các cổng sau chưa bị chiếm dụng trên máy chủ: `3322`, `3324`, `8080`, `8081`, `8082`, `8083`.

---

## Steps (Các Bước Thực hiện)

### Bước 1: Chuẩn bị Cấu hình Môi trường
Di chuyển vào thư mục gốc của dự án và kiểm tra tệp biến môi trường `.env.example`:

```powershell
# Copy tệp cấu hình mẫu thành .env
Copy-Item .env.example .env
```

### Bước 2: Khởi động Cụm Dịch vụ
Khởi chạy toàn bộ cụm 5 container trong chế độ chạy nền (detached mode):

```powershell
# Bằng lệnh Docker Compose tiêu chuẩn:
docker compose up -d --build

# Hoặc sử dụng script tự động hóa có sẵn của dự án:
.\scripts\docker_up.ps1
```

### Bước 3: Theo dõi Quá trình Khởi động
Kiểm tra danh sách và trạng thái các container:

```powershell
docker compose ps
```
*Kết quả kỳ vọng:*
```text
NAME            IMAGE                              STATUS                   PORTS
immudb          codenotary/immudb:latest           Up (healthy)             0.0.0.0:3322->3322/tcp, 0.0.0.0:3324->3324/tcp
mock-llm        ei-evidence-platform-mock-llm      Up (healthy)             0.0.0.0:8080->8080/tcp
ledger-worker   ei-evidence-platform-ledger-worker Up (healthy)             0.0.0.0:8083->8083/tcp
gateway         ei-evidence-platform-gateway       Up (healthy)             0.0.0.0:8081->8081/tcp
approval        ei-evidence-platform-approval      Up (healthy)             0.0.0.0:8082->8082/tcp
```

---

## Verification (Kiểm tra & Xác minh)

Chạy script kiểm tra sức khỏe tự động của toàn bộ cụm:

```powershell
.\scripts\healthcheck.ps1
```

Hoặc kiểm tra thủ công từng endpoint qua lệnh curl:
```powershell
# 1. Gateway
curl http://localhost:8081/health

# 2. Approval UI Service
curl http://localhost:8082/health

# 3. Ledger Worker
curl http://localhost:8083/health

# 4. Mock LLM
curl http://localhost:8080/health
```
*Tất cả endpoint đều phải trả về `HTTP 200` kèm `status: OK` hoặc `healthy`.*

Truy cập giao diện Web UI Phê duyệt tại trình duyệt:
👉 **`http://localhost:8082`**

---

## Troubleshooting (Xử lý Sự cố Thường gặp)

### 1. Lỗi đụng độ cổng (Port Conflict)
- **Hiện tượng**: `bind: address already in use` trên cổng 8081 hoặc 3322.
- **Khắc phục**: Dùng `netstat -ano | findstr <port>` để tìm tiến trình đang chiếm cổng và đóng tiến trình đó, hoặc chỉnh sửa cổng host trong `docker-compose.yml`.

### 2. immudb không sẵn sàng kịp thời
- **Hiện tượng**: `ledger-worker` restart liên tục do phụ thuộc vào `immudb`.
- **Khắc phục**: Chờ thêm 5-10 giây để immudb hoàn tất khởi tạo schema nội bộ. `depends_on: { immudb: { condition: service_healthy } }` trong docker-compose sẽ tự động xử lý chu kỳ này.

### 3. Dừng và giải phóng cụm container
```powershell
.\scripts\docker_down.ps1
# Hoặc:
docker compose down -v
```

---

## 4. Tài liệu Vận hành & Ứng phó Sự cố Nâng cao
Để xem chi tiết các kịch bản sự cố sản xuất (immudb downtime, tràn DiskWAL, nghẽn hàng đợi ring-buffer, bão lỗi 403 Shadow AI, hoặc lỗi thẩm định cryptographic pack), vui lòng tham khảo:
👉 **[SRE Incident Runbook & Operational Playbook](sre-incident-runbook.md)**
