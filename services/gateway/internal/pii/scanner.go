package pii

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var (
	// Bank Account: 8 to 16 digits preceded by keywords STK, TK, tài khoản, tai khoan, account
	bankRegex = regexp.MustCompile(`(?i)(?:STK|TK|tài khoản|tai khoan|account)[\s:]*([0-9]{8,16})`)

	// 12-digit CCCD: starts with 0, followed by 11 digits
	cccdRegex = regexp.MustCompile(`\b0\d{11}\b`)

	// Phone: +84 followed by [3,5,7,8,9] and 8 digits, or domestic 0 followed by [3,5,7,8,9] and 8 digits
	phoneRegex = regexp.MustCompile(`(?:\+84[35789]\d{8}|\b0[35789]\d{8})\b`)
)

// Sanitize normalizes input text prior to PII regex scanning:
// 1. Strips zero-width and invisible unicode codepoints (\u200b, \u200c, \u200d, \ufeff, \u00ad).
// 2. Translates full-width unicode numerals (\uff10-\uff19 / ０-９) to standard ASCII digits ('0'-'9').
// 3. Normalizes non-standard unicode whitespace (e.g. \u00a0, \u3000) to standard ASCII spaces.
func Sanitize(text string) string {
	if len(text) == 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(len(text))

	for _, r := range text {
		switch {
		case r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff' || r == '\u00ad':
			// Strip zero-width formatting and soft hyphen characters
			continue
		case r >= '\uff10' && r <= '\uff19':
			// Translate full-width unicode digit (０-９) to standard ASCII digit (0-9)
			b.WriteRune('0' + (r - '\uff10'))
		case unicode.IsSpace(r) && r != '\n' && r != '\r' && r != '\t':
			// Normalize exotic unicode whitespace (NBSP, em space, ideographic space) to standard ASCII space
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}

// MaskCCCD masks a 12-digit CCCD string to retain first 3 and last 3 digits.
func MaskCCCD(val string) string {
	if len(val) < 6 {
		return val
	}
	return val[:3] + "******" + val[len(val)-3:]
}

// MaskPhone masks a phone number string:
// - Domestic (0912345678): 091****678
// - International (+84903112233): +8490****233
func MaskPhone(val string) string {
	if strings.HasPrefix(val, "+84") {
		if len(val) >= 8 {
			return val[:5] + "****" + val[len(val)-3:]
		}
	} else if strings.HasPrefix(val, "0") {
		if len(val) >= 6 {
			return val[:3] + "****" + val[len(val)-3:]
		}
	}
	return val
}

// MaskBankAccount masks an 8-16 digit bank account number to retain first 4 and last 4 digits.
func MaskBankAccount(val string) string {
	if len(val) >= 8 {
		return val[:4] + "******" + val[len(val)-4:]
	}
	return "******"
}

// ScanAndMask scans the input text following the strict disambiguation hierarchy:
// 1. Bank Account (with context keywords)
// 2. 12-digit CCCD
// 3. Domestic & International Phone
// It returns the sanitized text and a sorted, deduplicated slice of detected PII labels.
func ScanAndMask(text string) (string, []string) {
	if len(text) == 0 {
		return "", []string{}
	}

	result := Sanitize(text)
	if len(result) == 0 {
		return "", []string{}
	}

	detectedMap := make(map[string]bool)

	// 1. Bank Account (Right-to-left replacement to preserve byte offsets)
	bankMatches := bankRegex.FindAllStringSubmatchIndex(result, -1)
	if len(bankMatches) > 0 {
		for i := len(bankMatches) - 1; i >= 0; i-- {
			sub := bankMatches[i]
			// sub[2], sub[3] are the start and end of capture group 1 (the digits)
			if sub[2] != -1 && sub[3] != -1 {
				accDigits := result[sub[2]:sub[3]]
				maskedAcc := MaskBankAccount(accDigits)
				result = result[:sub[2]] + maskedAcc + result[sub[3]:]
				detectedMap[LabelBankAccount] = true
			}
		}
	}

	// 2. CCCD (12 digits starting with 0)
	if cccdRegex.MatchString(result) {
		result = cccdRegex.ReplaceAllStringFunc(result, func(m string) string {
			detectedMap[LabelCCCD] = true
			return MaskCCCD(m)
		})
	}

	// 3. Phone (+84 or 0 prefix)
	if phoneRegex.MatchString(result) {
		result = phoneRegex.ReplaceAllStringFunc(result, func(m string) string {
			detectedMap[LabelPhone] = true
			return MaskPhone(m)
		})
	}

	var detected []string
	for k := range detectedMap {
		detected = append(detected, k)
	}
	sort.Strings(detected)
	if detected == nil {
		detected = []string{}
	}

	return result, detected
}

// MaskMapValues recursively scans and masks string values within a map.
// Returns a new map with masked values and the aggregated detected PII labels.
func MaskMapValues(input map[string]interface{}) (map[string]interface{}, []string) {
	if input == nil {
		return nil, []string{}
	}

	detectedSet := make(map[string]bool)
	output := make(map[string]interface{}, len(input))

	for k, v := range input {
		maskedVal, detected := maskInterface(v)
		output[k] = maskedVal
		for _, d := range detected {
			detectedSet[d] = true
		}
	}

	var labels []string
	for l := range detectedSet {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	if labels == nil {
		labels = []string{}
	}

	return output, labels
}

func maskInterface(v interface{}) (interface{}, []string) {
	switch val := v.(type) {
	case string:
		masked, detected := ScanAndMask(val)
		return masked, detected
	case map[string]interface{}:
		return MaskMapValues(val)
	case []interface{}:
		var allDetected []string
		newSlice := make([]interface{}, len(val))
		for i, item := range val {
			mItem, detected := maskInterface(item)
			newSlice[i] = mItem
			allDetected = append(allDetected, detected...)
		}
		return newSlice, allDetected
	default:
		return v, nil
	}
}
