# How to Verify an Evidence Pack Offline

Hướng dẫn kiểm toán viên độc lập sử dụng công cụ dòng lệnh `ai-evidence-cli` để thẩm định tính toàn vẹn và giá trị pháp lý của hồ sơ chứng cứ trong môi trường hoàn toàn cô lập mạng (Air-gapped).

---

## Prerequisites
- Tệp thực thi `ai-evidence-cli.exe` (đã biên dịch sẵn trong `cli/ai-evidence-cli/`).
  - Hoặc tự biên dịch từ mã nguồn Go:
    ```powershell
    cd cli/ai-evidence-cli
    go build -o ai-evidence-cli.exe main.go
    ```
- Tệp hồ sơ chứng cứ cần kiểm tra (ví dụ: `evidence_pack.zip`).
- Không yêu cầu kết nối mạng, không cần cơ sở dữ liệu hay máy chủ.

---

## Steps (Các Bước Thực hiện)

### Bước 1: Thẩm định Nhanh Hồ sơ Chứng cứ
Chạy lệnh kiểm tra tính toàn vẹn:

```powershell
.\ai-evidence-cli.exe verify evidence_pack.zip
```

*Nếu hồ sơ hoàn toàn hợp lệ:*
```text
======================================================================
AI EVIDENCE PACK VERIFICATION REPORT
======================================================================
Target Pack : evidence_pack.zip
Decision ID : dec-ml-88371923
Status      : VERIFICATION_SUCCESS
Exit Code   : 0
======================================================================
[PASS] Layer 1: Manifest Integrity & File Hashes
[PASS] Layer 2: RFC 6962 / 9162 Merkle Tree Proof & Root Recalculation
[PASS] Layer 3: Digital Signature & RFC 8785 Canonical JSON Verification
[PASS] Layer 4: X.509 Certificate Chain & Trust Validation
[PASS] Layer 5: Governance Policies (4-Eyes Separation & Dwell Time)
======================================================================
```
Kiểm tra mã thoát (Exit Code):
```powershell
$LASTEXITCODE # Trả về 0
```

---

### Bước 2: Thẩm định Chi tiết Từng Lớp với cờ `--verbose`
Khi cần xem nhật ký pháp y chi tiết của từng bước băm và giải mã:

```powershell
.\ai-evidence-cli.exe verify evidence_pack.zip -v
```

*Bảng log hiển thị:*
- Digest SHA-256 từng file trong manifest.
- Thuật toán tái tạo Root Hash Merkle từ các node láng giềng trong `audit_path`.
- Dấu thời gian RFC 3161 được giải mã từ ASN.1 DER.
- Danh tính và thuật toán ký (RSA-PSS, ECDSA P-256) của từng người duyệt.

---

### Bước 3: Xuất Báo cáo JSON cho Hệ thống Kiểm toán Tự động
```powershell
.\ai-evidence-cli.exe verify evidence_pack.zip --json > audit_result.json
```
Tệp `audit_result.json` sẽ chứa cấu trúc chuẩn bao gồm: `status`, `exit_code`, `decision_id`, và chi tiết từng layer `checks`.

---

### Bước 4: Kiểm tra Phát hiện Hồ sơ Bị Giả mạo (Forensic Tamper Detection)
Bạn có thể thử nghiệm trên các tệp mẫu kiểm thử đối kháng trong thư mục `tests/fixtures/evidence_packs/`:

```powershell
# 1. Hồ sơ bị sửa đổi nội dung quyết định sau khi ký
.\ai-evidence-cli.exe verify tests/fixtures/evidence_packs/tampered_manifest.zip
# Thoát với Exit Code 1 (EXIT_MANIFEST_FAIL)

# 2. Hồ sơ bị thay đổi chuỗi cây Merkle
.\ai-evidence-cli.exe verify tests/fixtures/evidence_packs/tampered_merkle.zip
# Thoát với Exit Code 2 (EXIT_MERKLE_FAIL)

# 3. Hồ sơ có chữ ký số giả mạo
.\ai-evidence-cli.exe verify tests/fixtures/evidence_packs/invalid_signature.zip
# Thoát với Exit Code 3 (EXIT_SIGNATURE_FAIL)

# 4. Hồ sơ vi phạm chính sách 4-mắt (1 người duyệt 2 lần hoặc tự duyệt)
.\ai-evidence-cli.exe verify tests/fixtures/evidence_packs/policy_violation_pack.zip
# Thoát với Exit Code 5 (EXIT_POLICY_FAIL)
```

---

## Verification (Bảng Đối chiếu Mã Thoát)

Luôn kiểm tra mã thoát `$LASTEXITCODE` trong script tự động hóa:
- **`0`**: Chứng cứ hợp lệ tuyệt đối (`VERIFICATION_SUCCESS`).
- **`1` – `5`**: Bằng chứng bị xâm phạm hoặc vi phạm chính sách kiểm soát.
- **`6`**: Lỗi tệp nén hoặc định dạng không thể đọc.
