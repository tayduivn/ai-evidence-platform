package pii

const (
	LabelCCCD        = "CCCD"
	LabelPhone       = "PHONE"
	LabelBankAccount = "BANK_ACCOUNT"
)

// ScanResult contains the sanitized text and sorted unique detected PII categories.
type ScanResult struct {
	MaskedText    string   `json:"masked_text"`
	DetectedTypes []string `json:"detected_types"`
}
