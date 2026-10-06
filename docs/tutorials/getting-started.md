# Getting Started with AI Evidence Platform: From Zero to Verified Evidence in 15 Minutes

Hướng dẫn thực hành từng bước từ đầu dành cho người mới: khởi động hệ thống, gửi yêu cầu suy luận qua Gateway, kích hoạt phê duyệt người kiểm soát 4-mắt, và thẩm định hồ sơ chứng cứ ngoại tuyến bằng CLI.

---

## Bạn Sẽ Xây dựng Được Điều Gì?
Khi hoàn thành bài hướng dẫn này, bạn sẽ nắm được toàn bộ vòng đời của một quyết định AI có tính pháp lý:
1. Gửi prompt chứa dữ liệu nhạy cảm (CCCD, SĐT) qua AI Gateway và quan sát khả năng che giấu PII tự động.
2. Gửi quyết định rủi ro cao và nhận về mã phản hồi `202 Accepted` (chặn dòng chờ duyệt).
3. Đóng vai trò 2 người kiểm soát độc lập trên Web UI để phê duyệt và ký số điện tử.
4. Xuất và dùng công cụ dòng lệnh độc lập để chứng minh tính toàn vẹn của hồ sơ chứng cứ mà không cần kết nối mạng.

---

## Yêu cầu Chuẩn bị
- Đã cài đặt **Docker Desktop** (hoặc Docker Engine).
- **Python 3.9+** (đã cài `requests`).
- Tối thiểu 4GB RAM trống.

---

## Bước 1: Khởi động Cụm Dịch vụ (Time to First Result < 3 phút)

Mở terminal PowerShell tại thư mục dự án và chạy:

```powershell
# 1. Khởi động cụm 5 container
docker compose up -d --build
```
*Đợi khoảng 30–60 giây để các container hoàn tất khởi động.*

Kiểm tra trạng thái sẵn sàng:
```powershell
curl http://localhost:8081/health
```
**Kết quả hiển thị trên màn hình:**
```json
{"status":"healthy","service":"gateway","version":"0.3.0"}
```
🎉 **Chúc mừng!** Cụm dịch vụ Gateway, immudb, Approval UI và Mock LLM đã sẵn sàng.

---

## Bước 2: Gửi Yêu cầu Suy luận LLM & Xem Bộ lọc PII Hoạt động

Mở terminal và thực hiện gọi API suy luận qua AI Gateway:

```powershell
$headers = @{
    "Content-Type" = "application/json"
    "X-AI-System-ID" = "customer-assistant-llm"
}

$body = @{
    "model" = "gpt-4o"
    "messages" = @(
        @{ "role" = "user"; "content" = "Xin chào, khách hàng CCCD 001234567890 và SĐT 0987654321 cần tư vấn gói bảo hiểm." }
    )
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8081/v1/chat/completions" -Method Post -Headers $headers -Body $body
$response.choices[0].message.content
```

**Điều gì vừa xảy ra trong nền?**
- AI Gateway đã xác thực mã `customer-assistant-llm` trong AI Registry.
- Bộ lọc PII tự động quét và che giấu thông tin: CCCD `001234567890` và SĐT `0987654321` được che thành `************` và `**********` trước khi lưu vết vào sổ cái bất biến immudb.

---

## Bước 3: Gửi Quyết định Rủi ro Cao Yêu cầu Người Duyệt (Intercept 202)

Bây giờ chúng ta gửi một quyết định cấp tín dụng vượt hạn mức tự động:

```powershell
$headers["X-Require-Approval"] = "true"
$bodyLoan = @{
    "model" = "gpt-4o"
    "messages" = @(
        @{ "role" = "user"; "content" = "Đề xuất phê duyệt hạn mức thẻ tín dụng 200,000,000 VNĐ." }
    )
    "requires_approval" = $true
} | ConvertTo-Json

try {
    $res = Invoke-WebRequest -Uri "http://localhost:8081/v1/chat/completions" -Method Post -Headers $headers -Body $bodyLoan
} catch {
    $res = $_.Exception.Response
}

$decisionInfo = $res.Content | ConvertFrom-Json
Write-Output "HTTP Status: $($res.StatusCode)"
Write-Output "Decision ID: $($decisionInfo.decision_id)"
Write-Output "Poll URL   : $($decisionInfo.poll_url)"
```

**Kết quả:**
- Thay vì trả về kết quả ngay, Gateway trả về **HTTP 202 Accepted**.
- Quyết định được đưa vào hàng đợi `PENDING` và sinh ra một `decision_id` duy nhất.

---

## Bước 4: Trải nghiệm Phê duyệt 4-Mắt trên Web UI

1. Mở trình duyệt web tại địa chỉ: **`http://localhost:8082`**.
2. Bạn sẽ thấy quyết định vừa tạo nằm trong danh sách **Pending Approvals**.
3. Bấm vào quyết định để xem chi tiết:
   - Chú ý bộ đếm thời gian **Dwell Time** đang đếm giây.
   - Nút **Approve** sẽ bị khóa trong 10 giây đầu tiên để đảm bảo bạn đọc kỹ nội dung rủi ro.
4. **Phê duyệt bước 1**:
   - Nhập Approver ID: `auditor_1@corp.vn`.
   - Chọn Signer: `internal`.
   - Khi đồng hồ vượt qua 10s, bấm **Approve**.
   - Quyết định chuyển sang trạng thái: `APPROVED_1`.
5. **Phê duyệt bước 2 (Hoàn tất)**:
   - Đổi Approver ID thành `manager_2@corp.vn` (Quy tắc 4-mắt cấm `auditor_1` duyệt lần 2).
   - Đọc đủ thời gian và bấm **Approve**.
   - Trạng thái chuyển thành `APPROVED_FINAL` kèm theo chuỗi chữ ký số điện tử được niêm phong.

---

## Bước 5: Thẩm định Bằng chứng Ngoại tuyến bằng CLI

Bây giờ bạn đóng vai trò là một kiểm toán viên độc lập (Auditor) được cấp một tệp hồ sơ chứng cứ `valid_pack.zip`:

```powershell
# Chạy công cụ dòng lệnh độc lập Go
.\cli\ai-evidence-cli\ai-evidence-cli.exe verify tests/fixtures/evidence_packs/valid_pack.zip -v
```

**Màn hình hiển thị kết quả kiểm định 5 tầng:**
```text
======================================================================
AI EVIDENCE PACK VERIFICATION REPORT
======================================================================
Target Pack : tests/fixtures/evidence_packs/valid_pack.zip
Decision ID : dec-loan-20261005-001
Status      : VERIFICATION_SUCCESS
Exit Code   : 0
======================================================================
[OK] Layer 1: Manifest Integrity & File Hashes (sha256 matched)
[OK] Layer 2: RFC 6962 / 9162 Merkle Tree Proof (Leaf 1024 -> Root recalculated)
[OK] Layer 3: Digital Signature (RFC 8785 canonical payload + RSA-PSS valid)
[OK] Layer 4: X.509 Certificate Chain (Trust path verified against Root CA)
[OK] Layer 5: Policy Verification (4-Eyes separation valid, Dwell time: 14.5s >= 10s)
======================================================================
>>> RESULT: VERIFICATION_SUCCESS <<<
```

---

## Bạn Đã Hoàn Thành Những Gì? (What You Built)

Chỉ trong 15 phút, bạn đã tự tay vận hành một hệ thống bảo chứng AI toàn diện:
- ✅ Thiết lập và vận hành một AI Gateway có khả năng khử định danh PII Việt Nam và ngăn chặn Shadow AI.
- ✅ Áp dụng cơ chế kiểm soát con người 4-mắt chống duyệt bừa bằng đo lường thời gian đọc thực tế.
- ✅ Ký số điện tử và lưu trữ sự kiện vào sổ cái Merkle chống chối bỏ.
- ✅ Sử dụng công cụ độc lập `ai-evidence-cli` để chứng minh tính toàn vẹn của hồ sơ chứng cứ trong môi trường air-gapped.

### Các Bước Tiếp Theo
- Tham khảo [How-to Integrate Client SDKs](../how-to/how-to-use-client-sdks.md) để nhúng vào pipeline ML của bạn.
- Đọc [Architecture & Cryptography](../explanation/architecture-and-cryptography.md) để hiểu sâu hơn về toán học mật mã cây Merkle và RFC 3161.
