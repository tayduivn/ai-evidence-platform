# Human-in-the-Loop Governance & Pluggable Digital Signing

Tài liệu giải thích nguyên lý thiết kế cơ chế kiểm soát con người (Human-in-the-Loop), quy tắc 4-mắt (Four-Eyes Principle), phòng ngừa duyệt bừa (Anti-Rubberstamping), và kiến trúc chữ ký số đa hình (Pluggable Signers).

---

## 1. Bản chất Vấn đề Kiểm soát AI (The Governance Challenge)

Các quy định an toàn AI quốc tế (EU AI Act) và định hướng pháp lý Việt Nam đều yêu cầu mức độ giám sát của con người đối với các quyết định AI có rủi ro cao:
- **Nguy cơ thông đồng hoặc tự tạo tự duyệt**: Nhân viên kinh doanh có thể cố tình đưa dữ liệu khống vào mô hình AI rồi tự bấm phê duyệt cho khoản vay của người thân.
- **Hiện tượng Duyệt bừa (Rubber-stamping)**: Người duyệt bấm nút "Chấp thuận" hàng loạt trong vài giây mà không thực sự đọc giải trình SHAP hoặc cảnh báo rủi ro của mô hình.
- **Sự đa dạng của hạ tầng chữ ký số tại Việt Nam**: Doanh nghiệp vừa cần ký số nội bộ nhanh chóng qua SSO, vừa phải tuân thủ chuẩn chữ ký số pháp lý theo Nghị định 130/2018/NĐ-CP (USB Token PKCS#11) hoặc Thông tư 16/2019/TT-BTTTT (Remote Signing Cloud Signature Consortium).

---

## 2. Máy Trạng thái 5 Nấc & Quy tắc 4-Mắt (Four-Eyes State Machine)

Hệ thống triển khai máy trạng thái nghiêm ngặt với 5 nấc kiểm duyệt:

```text
                  ┌──────────────┐
                  │   PENDING    │
                  └──────┬───────┘
                         │
        ┌────────────────┼────────────────┐
        │ [Action=APPROVE]│                │ [Action=REJECT]
        │ Approver != Creator             │ Approver != Creator
        ▼                                 ▼
┌──────────────┐                   ┌──────────────┐
│  APPROVED_1  │                   │   REJECTED   │
└───────┬──────┘                   └──────────────┘
        │                                ▲
        │ [Action=APPROVE]                │
        │ Approver_2 != Approver_1        │
        │ Approver_2 != Creator           │
        ▼                                 │
┌──────────────┐                          │
│APPROVED_FINAL├──────────────────────────┘
└──────────────┘   (Nếu có khiếu nại/hủy bỏ)
```

### Các Ràng buộc Bắt buộc:
1. **Loại trừ Người tạo (No Self-Approval)**: `creator_id != approver_id`. Người gửi quyết định vào hệ thống không bao giờ có thể tự ký duyệt cho chính mình.
2. **Hai người duyệt độc lập**: Quyết định chuyển sang `APPROVED_1` sau người duyệt đầu tiên, và chỉ đạt `APPROVED_FINAL` khi có người duyệt thứ hai độc lập xác nhận.
3. **Tính Bất biến khi Hoàn tất (Terminal State)**: Một khi quyết định đã ở trạng thái `APPROVED_FINAL` hoặc `REJECTED`, không ai có quyền mở lại hoặc thay đổi dữ liệu đã ký.

---

## 3. Cơ chế Chống Duyệt Bừa (Anti-Rubberstamping)

Thay vì chỉ kiểm tra nút bấm, hệ thống tích hợp động cơ **Dwell Time Engine**:
- **Phiên duyệt độc nhất (Session Heartbeat)**: Khi người duyệt mở trang chi tiết quyết định trên Web UI, trình duyệt sinh một `session_token` ngẫu nhiên và gửi heartbeat mỗi 1.0 giây về endpoint `/api/v1/approvals/{id}/dwell`.
- **Đo lường thời gian đọc thực tế**: Máy chủ tích lũy số mili-giây người duyệt thực sự xem màn hình.
- **Ngưỡng an toàn**: Nếu thời gian đọc chưa đạt ngưỡng tối thiểu cấu hình (mặc định: `10 giây`), nút duyệt trên giao diện sẽ bị khóa và máy chủ sẽ trả về lỗi `HTTP 400 Insufficient dwell time` nếu có lệnh gọi API gian lận trực tiếp.

---

## 4. Kiến trúc Khóa Mịn Per-Decision (`KeyMutex`)

Trong môi trường ngân hàng có hàng trăm giao dịch phê duyệt đồng thời:
- **Nếu dùng Global Mutex**: Mọi thao tác ký số (thường mất 500ms - 2000ms khi gọi dịch vụ Remote Signing qua mạng) sẽ làm nghẽn toàn bộ hệ thống phê duyệt của mọi chi nhánh khác.
- **Giải pháp `KeyMutex`**:
  - Khóa mutex độc lập theo từng `decision_id` cụ thể (`sync.Mutex` có cơ chế Reference Counting).
  - Hai người cùng duyệt trên cùng một quyết định sẽ được tuần tự hóa an toàn (ngăn chặn race condition).
  - Hàng nghìn người duyệt trên các quyết định khác nhau chạy song song 100% không bị ảnh hưởng.

---

## 5. Kiến trúc Chữ Ký Số Đa Hình (Pluggable Signers)

Interface `Signer` trong Go cho phép cắm/rút linh hoạt 3 cơ chế ký số:

```go
type Signer interface {
    Type() string
    Sign(ctx context.Context, canonicalPayload []byte) (signatureHex string, certPEM []byte, err error)
    Verify(canonicalPayload []byte, signatureHex string, certPEM []byte) error
}
```

1. **Internal Key Signer (`signer_type: internal`)**:
   - Sử dụng cặp khóa RSA-2048 hoặc ECDSA P-256 nội bộ.
   - Thích hợp cho các quyết định nội bộ có lưu lượng cao, xác thực định danh qua SSO/OAuth2.
2. **CA VN USB Token (`signer_type: ca_vn_token`)**:
   - Cắm nối với thiết bị Token phần cứng của các nhà mạng (VNPT-CA, Viettel-CA, FPT-CA, BkavCA) qua chuẩn PKCS#11 theo Nghị định 130/2018/NĐ-CP.
   - Khóa riêng được bảo vệ trong chip mật mã phần cứng, không thể trích xuất ra ngoài.
3. **CA VN Remote Signing (`signer_type: ca_vn_remote`)**:
   - Tích hợp dịch vụ Ký số từ xa theo Thông tư 16/2019/TT-BTTTT qua giao thức Cloud Signature Consortium (CSC REST API).
   - Xác thực người ký qua OTP/FIDO2 trên điện thoại di động, phù hợp cho cán bộ phê duyệt từ xa.
