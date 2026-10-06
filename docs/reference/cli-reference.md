# CLI Reference: ai-evidence-cli

Tài liệu tham chiếu chi tiết công cụ dòng lệnh độc lập **`ai-evidence-cli`** (phiên bản binary: `ai-evidence-cli.exe`), phục vụ thẩm định hồ sơ chứng cứ ngoại tuyến (Offline Verification) trong môi trường biệt lập (Air-gapped / Forensic Audit).

---

## 1. Cú pháp Tổng quát (Usage)

```bash
ai-evidence-cli <command> [arguments] [flags]
```

### Các Lệnh Hỗ trợ (Commands)
- `verify <pack.zip>`: Thẩm định tính toàn vẹn mật mã học và tuân thủ chính sách của hồ sơ chứng cứ.
- `inspect <pack.zip>`: Trích xuất và hiển thị bảng tổng quan pháp y dưới dạng bảng dễ đọc hoặc JSON.
- `pack [options]`: Đóng gói hồ sơ chứng cứ thành tệp ZIP tất định (deterministic bit-for-bit).
- `version`: Hiển thị thông tin phiên bản và commit build của công cụ.
- `help`: Hiển thị trợ giúp nhanh.

---

## 2. Chi tiết Lệnh `verify`

Thực hiện quy trình thẩm định 5 tầng mật mã học độc lập mà không cần kết nối tới bất kỳ máy chủ nào.

```bash
ai-evidence-cli verify <pack.zip> [flags]
```

### Flags
| Flag | Viết tắt | Kiểu dữ liệu | Mặc định | Ý nghĩa |
|---|---|---|---|---|
| `--min-dwell` | `-d` | Số nguyên | `10` | Ngưỡng thời gian đọc tối thiểu (giây) để chống duyệt bừa. |
| `--json` | `-j` | Boolean | `false` | Xuất kết quả chi tiết dưới dạng JSON có cấu trúc. |
| `--verbose` | `-v` | Boolean | `false` | Hiển thị chi tiết từng bước kiểm tra của 5 tầng xác thực. |
| `--root-ca` | `-c` | Đường dẫn | `""` | Ghi đè Root CA certificate PEM để kiểm tra chứng thư số tùy chỉnh. |

### Ví dụ Sử dụng
```bash
# 1. Xác minh cơ bản
ai-evidence-cli verify evidence_pack.zip

# 2. Xác minh với cấu hình thời gian đọc tối thiểu 15 giây và xuất chi tiết
ai-evidence-cli verify evidence_pack.zip -d 15 -v

# 3. Xuất kết quả JSON phục vụ tích hợp tự động vào CI/CD hoặc SIEM
ai-evidence-cli verify evidence_pack.zip --json > report.json
```

### Bảng Mã Thoát Chuẩn hóa (Exit Codes)
Lệnh `verify` bảo đảm tính tất định 100% với các mã thoát sau:

| Mã thoát | Tên hằng số | Thông báo chuẩn | Nguyên nhân |
|---|---|---|---|
| **`0`** | `ExitSuccess` | `VERIFICATION_SUCCESS` | Tất cả 5 tầng kiểm tra tính toàn vẹn và chính sách đều đạt chuẩn tuyệt đối. |
| **`1`** | `ExitManifestFail` | `EXIT_MANIFEST_FAIL` | `manifest.json` bị thiếu, hỏng cú pháp, hoặc hash SHA-256 của tệp con không khớp. |
| **`2`** | `ExitMerkleFail` | `EXIT_MERKLE_FAIL` | Hash lá tính toán lại không khớp `leaf_hash` hoặc Audit Path không tái tạo được `root_hash`. |
| **`3`** | `ExitSignatureFail` | `EXIT_SIGNATURE_FAIL` | Chữ ký số không hợp lệ, bị sửa đổi, hoặc payload chuẩn hóa RFC 8785 bị sai lệch. |
| **`4`** | `ExitCertFail` | `EXIT_CERT_FAIL` | Chứng thư số của người ký hết hạn, bị thu hồi, hoặc chuỗi CA không bắt nguồn từ Root CA tin cậy. |
| **`5`** | `ExitPolicyFail` | `EXIT_POLICY_FAIL` | Vi phạm quy tắc nghiệp vụ: người tạo tự duyệt, trùng lặp người duyệt 4-mắt, hoặc thời gian đọc nhỏ hơn `--min-dwell`. |
| **`6`** | `ExitGeneralFail` | `EXIT_GENERAL_FAIL` | Tệp tin không tồn tại, tệp ZIP hỏng, tấn công Zip Slip, hoặc lỗi I/O nghiêm trọng. |

---

## 3. Chi tiết Lệnh `inspect`

Trích xuất thông tin tóm tắt pháp y của quyết định từ hồ sơ chứng cứ mà không cần giải nén thủ công.

```bash
ai-evidence-cli inspect <pack.zip> [flags]
```

### Flags
| Flag | Viết tắt | Kiểu dữ liệu | Mặc định | Ý nghĩa |
|---|---|---|---|---|
| `--json` | `-j` | Boolean | `false` | Xuất toàn bộ báo cáo phân tích pháp y dưới dạng JSON. |
| `--show-payloads` | N/A | Boolean | `false` | Hiển thị toàn văn nội dung đầu vào/đầu ra (mặc định bị ẩn để bảo vệ quyền riêng tư). |

### Ví dụ Sử dụng
```bash
ai-evidence-cli inspect evidence_pack.zip
```
Output hiển thị trên terminal:
```text
======================================================================
EVIDENCE PACK FORENSIC SUMMARY
======================================================================
Decision ID   : dec-ml-88371923
AI System ID  : credit-scoring-ml (v2.1.0)
Timestamp     : 2026-10-06T03:15:20Z
Root Hash     : 8f9b3c4d12...
Merkle Index  : Leaf #1024 / Total 2048
Approvers     : 
  - [Step 1] auditor_1@corp.vn (Internal RSA-2048) | Dwell: 12.4s
  - [Step 2] manager_2@corp.vn (CA VN USB Token)   | Dwell: 18.2s
RFC 3161 TSA  : Verified (Anchor Time: 2026-10-06T03:16:00Z)
======================================================================
```

---

## 4. Chi tiết Lệnh `pack`

Đóng gói các tệp chứng cứ thành một Evidence Pack dạng ZIP theo cấu trúc tất định (Deterministic bit-for-bit packaging).

```bash
ai-evidence-cli pack [flags]
```

### Flags
| Flag | Viết tắt | Kiểu dữ liệu | Ý nghĩa |
|---|---|---|---|
| `--dir` | N/A | Đường dẫn thư mục | Đóng gói toàn bộ các tệp chứng cứ từ thư mục nguồn. |
| `--events` | N/A | Đường dẫn tệp | Đường dẫn tới `events.json`. |
| `--proof` | N/A | Đường dẫn tệp | Đường dẫn tới `merkle_proof.json`. |
| `--signatures` | N/A | Đường dẫn thư mục | Thư mục chứa các tệp chữ ký số `signature_*.json`. |
| `--certs` | N/A | Đường dẫn thư mục | Thư mục chứa `signer_*.pem` và `root_ca.pem`. |
| `--anchor` | N/A | Đường dẫn tệp | Đường dẫn tới tệp dấu thời gian RFC 3161 (`.tsr`). |
| `--output` | `-o` | Đường dẫn tệp | **Bắt buộc**: Đường dẫn tệp ZIP đầu ra. |

### Ví dụ Sử dụng
```bash
ai-evidence-cli pack --dir ./evidence_staging -o ./export/evidence_pack_dec_88371923.zip
```
