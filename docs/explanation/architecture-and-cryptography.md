# Architecture & Cryptography: Why Tamper-Evident Design Matters

Tài liệu giải thích sâu về lý do lựa chọn kiến trúc mật mã học, mô hình đe dọa (Threat Model) và cơ chế chống chối bỏ của nền tảng **AI Evidence & Accountability Platform**.

---

## 1. Vấn đề Cốt lõi (The Problem)

Khi các mô hình AI/ML được trao quyền đưa ra hoặc đề xuất các quyết định có tính pháp lý cao (duyệt vay tín dụng, thẩm định bảo hiểm, phê duyệt y khoa, phân loại hồ sơ tuyển dụng):
1. **Rủi ro sửa đổi nhật ký (Database Tampering)**: Nếu chỉ lưu log vào cơ sở dữ liệu quan hệ truyền thống (MySQL, PostgreSQL), một quản trị viên cơ sở dữ liệu (DBA) có quyền root hoàn toàn có thể chạy câu lệnh `UPDATE` hoặc `DELETE` để xóa bỏ chứng cứ hoặc làm sai lệch kết quả suy luận nhằm chối bỏ trách nhiệm.
2. **Sai lệch định dạng JSON (JSON Canonicalization Drift)**: Cùng một đối tượng dữ liệu JSON, các ngôn ngữ khác nhau (Go, Python, Java) có thể sắp xếp các khóa (keys), khoảng trắng và định dạng số thực khác nhau. Một chữ ký số ký trên JSON ở Go sẽ bị xác thực thất bại trên Java nếu không có chuẩn tắc hóa tất định.
3. **Mất an toàn khi sự cố sập nguồn (Crash Inconsistency)**: Nếu lưu trữ chỉ dựa trên bộ đệm RAM để tối ưu tốc độ, khi máy chủ bị mất điện đột ngột hoặc tiến trình bị crash, các quyết định vừa duyệt sẽ biến mất vĩnh viễn khỏi sổ cái.

---

## 2. Giải pháp Mật mã học (The Cryptographic Approach)

Hệ thống kết hợp ba tầng bảo chứng độc lập tạo thành chuỗi mắt xích mật mã học không thể phá vỡ:

```text
[Quyết định AI: Features + Score + Output]
                   │
                   ▼ (1. Chuẩn hóa tất định)
     RFC 8785 Canonical JSON (JCS)
                   │
                   ▼ (2. Băm định danh)
              SHA-256 Leaf Hash
                   │
         ┌─────────┴─────────┐
         ▼                   ▼ (3. Gom cây chống chối bỏ)
   RFC 6962 Leaf       Cây Merkle Nhị phân
   Prefix 0x00         Domain Separation (0x01 cho Node)
         │                   │
         │                   ▼
         │             Merkle Root Hash
         │                   │
         │                   ▼ (4. Neo pháp lý bên ngoài)
         │             RFC 3161 TSA Token
         │             (ASN.1 DER External Anchor)
         │
         ▼ (5. Ký số người kiểm soát)
   Pluggable Digital Signatures
   (Internal RSA/ECDSA, CA VN USB Token, Remote CSC)
         │
         ▼ (6. Đóng gói kiểm toán độc lập)
   Offline Evidence Pack (.zip)
```

### 2.1. Chuẩn hóa Tất định theo RFC 8785 (JCS)
- **Nguyên lý**: JSON Canonicalization Scheme (RFC 8785) sắp xếp tất cả các khóa của JSON Object theo thứ tự từ điển UTF-16 code units, chuẩn hóa số thực, loại bỏ toàn bộ khoảng trắng thừa, và chuẩn hóa escape sequences.
- **Lợi ích**: Bảo đảm payload đưa vào hàm băm `SHA256(canonical_bytes)` luôn cho ra cùng một digest byte-for-byte, bất kể được sinh ra từ Python, Go hay Java.

### 2.2. Cây Merkle RFC 6962 / RFC 9162 & Domain Separation
- **Phòng thủ Second-Preimage Attack**: Để chống việc kẻ tấn công tạo một node nội bộ giả mạo lá của cây Merkle, hệ thống áp dụng cơ chế Domain Separation:
  $$\text{Leaf Hash} = \text{SHA256}(0x00 \parallel \text{leaf\_data})$$
  $$\text{Interior Node Hash} = \text{SHA256}(0x01 \parallel \text{left\_hash} \parallel \text{right\_hash})$$
- **Audit Path ngắn gọn**: Người kiểm toán chỉ cần $\mathcal{O}(\log_2 N)$ phần tử để chứng minh một sự kiện nằm trong sổ cái $N$ sự kiện mà không cần đọc toàn bộ cơ sở dữ liệu.

### 2.3. Neo Dấu Thời gian RFC 3161 (TSA)
- Ngay cả khi toàn bộ máy chủ nội bộ bị thỏa hiệp hoặc chỉnh giờ BIOS, Root Hash của cây Merkle đã được gửi sang máy chủ TSA độc lập của cơ quan thẩm quyền để đóng dấu thời gian bằng chữ ký số bất đối xứng (ASN.1 DER). Do đó, thời điểm phát sinh sự kiện là không thể chối cãi.

---

## 3. Mô hình Đe dọa & Cơ chế Phòng thủ (Threat Model)

| Kịch bản Đe dọa | Kẻ tấn công | Cơ chế Phòng thủ của Nền tảng |
|---|---|---|
| **Sửa đổi bản ghi trong DB** | Quản trị viên hệ thống / Hacker | immudb lưu trữ dạng Append-Only Cryptographic Ledger; bất kỳ sửa đổi nào cũng làm gãy chuỗi Merkle Root Hash. |
| **Chối bỏ phê duyệt** | Người duyệt nói "Tôi không duyệt" | Chữ ký số X.509 PKCS#1v15 / PSS / ECDSA gắn trực tiếp với chứng thư số của cá nhân trên payload RFC 8785. |
| **Duyệt bừa không đọc** | Người duyệt bấm duyệt tức thì | Bộ đo Dwell Time Telemetry theo dõi thời gian đọc thực tế và phiên duyệt; từ chối mọi thao tác dưới 10 giây. |
| **Người tạo tự phê duyệt** | Nhân viên gian lận tự tạo & tự duyệt | Quy tắc 4-mắt kiểm tra định danh `creator_id != approver_id` và bắt buộc 2 người duyệt khác nhau (`APPROVED_1` và `APPROVED_FINAL`). |
| **Tấn công Zip Slip khi giải nén** | Hồ sơ chứng cứ độc hại | CLI kiểm tra chặt chẽ đường dẫn tệp con, chặn đứng mọi tệp có chứa `../` hoặc đường dẫn tuyệt đối. |
| **Né bộ lọc PII qua Unicode** | Người dùng gửi CCCD dạng `００１...` | Bộ lọc PII tự động loại bỏ ký tự zero-width và chuẩn hóa chữ số full-width Unicode về `0-9` trước khi regex. |

---

## 4. Đánh đổi Thiết kế (Trade-offs)

- **Tại sao dùng immudb thay vì Blockchain công khai?**
  - *Blockchain công khai (Ethereum, Solana)*: Phí giao dịch (gas fee) cao, thông lượng thấp (15-50 TPS), lộ dữ liệu nội bộ.
  - *immudb*: Tốc độ > 50,000 TPS, chi phí lưu trữ thấp, lưu trữ tại chỗ (on-premise), kết hợp cùng RFC 3161 TSA mang lại giá trị pháp lý tương đương mà không tốn phí gas.
- **Tại sao dùng Write-Ahead Log (DiskWAL) cục bộ?**
  - Thay vì để Gateway gọi trực tiếp cơ sở dữ liệu (làm tăng độ trễ p95 lên > 50ms), Gateway chỉ ghi vào hàng đợi và DiskWAL tuần tự (I/O append chỉ mất < 1ms), vừa đạt SLA độ trễ cao, vừa chống mất mát dữ liệu khi crash.
