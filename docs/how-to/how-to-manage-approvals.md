# How to Review and Approve AI Decisions (Human-in-the-Loop)

Hướng dẫn kiểm soát viên và quản lý cấp cao sử dụng giao diện Web UI Phê duyệt (`:8082`) để thực hiện quy trình duyệt 4-mắt, theo dõi thời gian đọc chống duyệt bừa và thực hiện ký số điện tử.

---

## Prerequisites
- Dịch vụ Approval Service đang chạy tại `http://localhost:8082`.
- Có ít nhất 1 quyết định AI đang ở trạng thái `PENDING` (sinh ra từ Gateway Intercept Mode hoặc SDK `request_approval`).

---

## Steps (Các Bước Thực hiện)

### Bước 1: Truy cập Giao diện Web UI Phê duyệt
Mở trình duyệt web và điều hướng tới:
👉 **`http://localhost:8082`**

Giao diện sẽ hiển thị danh sách các quyết định đang chờ duyệt (Pending Approvals) với các thông tin:
- **Decision ID** (Mã quyết định)
- **AI System ID** (Tên mô hình)
- **Score & Recommendation** (Điểm số rủi ro & đề xuất của AI)
- **Created At** (Thời điểm tạo)

---

### Bước 2: Xem Chi tiết Quyết định & Đọc Dữ liệu (Dwell Time Tracker)
1. Bấm vào một quyết định để mở màn hình thẩm định chi tiết.
2. Màn hình hiển thị:
   - Toàn bộ thuộc tính đầu vào (`features`), kết quả giải trình SHAP (`explanation`), và cảnh báo PII.
   - **Đồng hồ Dwell Time**: Một bộ đếm thời gian thực sẽ đếm ngược (hoặc tăng dần) thời gian bạn đang xem tài liệu.
3. **Lưu ý**: Nút **"Phê duyệt (Approve)"** sẽ bị làm mờ (disabled) cho tới khi bạn đã đọc đủ thời gian tối thiểu theo quy định (mặc định: **10 giây**).

---

### Bước 3: Người thứ nhất Phê duyệt (Step 1: APPROVED_1)
1. Chọn người duyệt: Điền email hoặc username (ví dụ: `auditor_1@corp.vn`).
   - *Quy tắc an toàn*: Không được trùng với `creator_id` của quyết định.
2. Chọn hình thức ký số:
   - `internal`: Ký bằng khóa điện tử nội bộ.
   - `ca_vn_token`: Ký bằng USB Token phần cứng.
   - `ca_vn_remote`: Ký số từ xa qua ứng dụng di động.
3. Bấm **"Phê duyệt (Approve)"** và nhập nhận xét (Comment).
4. **Kết quả**: Trạng thái quyết định chuyển sang `APPROVED_1` ("Đã duyệt bước 1 — Đang chờ người duyệt thứ hai").

---

### Bước 4: Người thứ hai Phê duyệt (Step 2: APPROVED_FINAL)
1. Đăng xuất hoặc đổi định danh sang tài khoản người duyệt thứ hai (ví dụ: `manager_2@corp.vn`).
2. Mở lại quyết định đó và đọc nội dung (đảm bảo đủ thời gian Dwell Time của người thứ hai).
3. Bấm **"Phê duyệt Hoàn tất (Final Approve)"**.
4. **Kết quả**:
   - Hệ thống tự động tổng hợp toàn văn sự kiện, chuẩn hóa theo chuẩn **RFC 8785 (JCS)**, tính hash và thực hiện ký số.
   - Trạng thái chuyển sang `APPROVED_FINAL`. Quyết định được niêm phong vĩnh viễn và đồng bộ vào immudb.

---

## Verification (Kiểm tra Tính Tuân thủ)

### Kiểm tra 1: Thử Nghiệm Tự Phê duyệt (Bị Chặn)
- Nhập `auditor_1@corp.vn` cho một quyết định mà `creator_id` cũng là `auditor_1@corp.vn`.
- Bấm Duyệt.
- **Xác nhận**: Giao diện và API lập tức từ chối với thông báo đỏ:
  `Error 400: Self-approval prohibited by Four-Eyes governance policy`.

### Kiểm tra 2: Thử Nghiệm Duyệt quá Nhanh (< 10 giây)
- Dùng công cụ gọi API trực tiếp không qua UI trong vòng 1 giây.
- **Xác nhận**: Máy chủ từ chối:
  `Error 400: Insufficient dwell time (elapsed: 1000ms, required: 10000ms)`.

---

## Troubleshooting

### Nút duyệt vẫn bị mờ sau 10 giây
- **Nguyên nhân**: Trình duyệt có thể đã bị mất tiêu điểm (tab bị ẩn) hoặc mạng bị gián đoạn khiến heartbeat dwell time không gửi được về máy chủ.
- **Khắc phục**: Giữ tab trình duyệt mở và tương tác cuộn trang để bộ đếm tiếp tục tính thời gian.
