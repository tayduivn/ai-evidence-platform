package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	ErrInvalidNumber = errors.New("canonical: NaN and Infinite numbers are not permitted in JSON")
	ErrInvalidUTF8   = errors.New("canonical: invalid UTF-8 string")
)

// Canonicalize takes arbitrary JSON bytes and transforms them into RFC 8785 canonical bytes.
func Canonicalize(jsonBytes []byte) ([]byte, error) {
	if !utf8.Valid(jsonBytes) {
		return nil, ErrInvalidUTF8
	}

	d := json.NewDecoder(bytes.NewReader(jsonBytes))
	d.UseNumber()

	var val any
	if err := d.Decode(&val); err != nil {
		return nil, fmt.Errorf("canonical: decode error: %w", err)
	}

	// Ensure there is no trailing data except whitespace
	var dummy any
	if err := d.Decode(&dummy); err != io.EOF {
		return nil, errors.New("canonical: unexpected trailing data after JSON object")
	}

	var buf bytes.Buffer
	if err := writeCanonicalValue(&buf, val); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Marshal serializes any Go value to RFC 8785 canonical JSON bytes.
func Marshal(v any) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return Canonicalize(b)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal error: %w", err)
	}
	return Canonicalize(raw)
}

// HashSHA256 returns the 32-byte SHA-256 hash and canonical bytes.
func HashSHA256(v any) ([32]byte, []byte, error) {
	canonBytes, err := Marshal(v)
	if err != nil {
		return [32]byte{}, nil, err
	}
	digest := sha256.Sum256(canonBytes)
	return digest, canonBytes, nil
}

// HashSHA256Hex returns the hex-encoded SHA-256 hash and canonical bytes.
func HashSHA256Hex(v any) (string, []byte, error) {
	digest, canonBytes, err := HashSHA256(v)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(digest[:]), canonBytes, nil
}

func writeCanonicalValue(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return writeCanonicalString(buf, val)
	case json.Number:
		return writeCanonicalNumber(buf, val.String())
	case float64:
		return writeCanonicalFloat(buf, val)
	case float32:
		return writeCanonicalFloat(buf, float64(val))
	case int:
		buf.WriteString(strconv.FormatInt(int64(val), 10))
		return nil
	case int64:
		buf.WriteString(strconv.FormatInt(val, 10))
		return nil
	case int32:
		buf.WriteString(strconv.FormatInt(int64(val), 10))
		return nil
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(val), 10))
		return nil
	case uint64:
		buf.WriteString(strconv.FormatUint(val, 10))
		return nil
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(val), 10))
		return nil
	case []any:
		return writeCanonicalArray(buf, val)
	case map[string]any:
		return writeCanonicalObject(buf, val)
	default:
		// Fallback via re-marshal
		raw, err := json.Marshal(val)
		if err != nil {
			return err
		}
		canon, err := Canonicalize(raw)
		if err != nil {
			return err
		}
		buf.Write(canon)
		return nil
	}
}

func writeCanonicalString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return ErrInvalidUTF8
	}
	buf.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(fmt.Sprintf(`\u00%02x`, r))
			} else {
				buf.WriteString(s[i : i+size])
			}
		}
		i += size
	}
	buf.WriteByte('"')
	return nil
}

func writeCanonicalNumber(buf *bytes.Buffer, numStr string) error {
	f, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return fmt.Errorf("canonical: invalid number '%s': %w", numStr, err)
	}
	return writeCanonicalFloat(buf, f)
}

func writeCanonicalFloat(buf *bytes.Buffer, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return ErrInvalidNumber
	}
	if f == 0.0 {
		buf.WriteString("0")
		return nil
	}

	formatted := formatECMAScriptNumber(f)
	buf.WriteString(formatted)
	return nil
}

// formatECMAScriptNumber formats float64 per ECMAScript 6 (7.1.12.1 ToString(x)).
func formatECMAScriptNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	isNegative := false
	if f < 0 {
		isNegative = true
		f = -f
	}

	// Format using Go's shortest round-trip representation ('g')
	s := strconv.FormatFloat(f, 'g', -1, 64)

	// Check if s contains scientific notation 'e'
	if strings.Contains(s, "e") {
		parts := strings.Split(s, "e")
		mantissa := parts[0]
		expStr := parts[1]
		expVal, _ := strconv.Atoi(expStr)

		// ECMAScript: use exponential notation only when expVal < -6 or expVal >= 21
		if expVal >= 21 || expVal < -6 {
			var normExp string
			if expVal > 0 {
				normExp = fmt.Sprintf("e+%d", expVal)
			} else {
				normExp = fmt.Sprintf("e%d", expVal)
			}
			res := mantissa + normExp
			if isNegative {
				return "-" + res
			}
			return res
		}

		// Otherwise, convert back to fixed decimal format
		s = strconv.FormatFloat(f, 'f', -1, 64)
	} else {
		// If float representation has no exponent, check if magnitude is >= 1e21
		if f >= 1e21 {
			s = strconv.FormatFloat(f, 'e', -1, 64)
			parts := strings.Split(s, "e")
			mantissa := parts[0]
			expStr := parts[1]
			expVal, _ := strconv.Atoi(expStr)
			s = fmt.Sprintf("%se+%d", mantissa, expVal)
		}
	}

	if isNegative {
		return "-" + s
	}
	return s
}

func writeCanonicalArray(buf *bytes.Buffer, arr []any) error {
	buf.WriteByte('[')
	for i, item := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonicalValue(buf, item); err != nil {
			return err
		}
	}
	buf.WriteByte(']')
	return nil
}

type kvPair struct {
	key string
	val any
}

func writeCanonicalObject(buf *bytes.Buffer, obj map[string]any) error {
	pairs := make([]kvPair, 0, len(obj))
	for k, v := range obj {
		pairs = append(pairs, kvPair{key: k, val: v})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return compareUTF16(pairs[i].key, pairs[j].key) < 0
	})

	buf.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonicalString(buf, p.key); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := writeCanonicalValue(buf, p.val); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// compareUTF16 compares two strings based on UTF-16 code units per RFC 8785 Section 3.2.3.
func compareUTF16(a, b string) int {
	uA := utf16.Encode([]rune(a))
	uB := utf16.Encode([]rune(b))
	minLen := len(uA)
	if len(uB) < minLen {
		minLen = len(uB)
	}
	for i := 0; i < minLen; i++ {
		if uA[i] < uB[i] {
			return -1
		} else if uA[i] > uB[i] {
			return 1
		}
	}
	if len(uA) < len(uB) {
		return -1
	} else if len(uA) > len(uB) {
		return 1
	}
	return 0
}
