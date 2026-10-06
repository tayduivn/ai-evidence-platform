package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
)

// TestAdversarial_AstralPlaneKeySorting stresses RFC 8785 UTF-16 code unit key sorting.
// Specifically, U+FFFF (BMP, 3-byte UTF-8 EF BF BF, UTF-16 code unit 0xFFFF)
// must sort AFTER U+10000 (Astral plane, 4-byte UTF-8 F0 90 80 80, UTF-16 surrogate pair D800 DC00).
func TestAdversarial_AstralPlaneKeySorting(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "U+10000 vs U+FFFF: UTF-16 D800 < FFFF, but UTF-8 F0 > EF (using UTF-8 literals)",
			input:    "{\"\uffff\": 1, \"\U00010000\": 2}",
			expected: "{\"\U00010000\":2,\"\uffff\":1}", // Notice: U+10000 comes FIRST!
		},
		{
			name:     "U+10000 vs U+FFFF: using JSON surrogate pairs \\uD800\\uDC00",
			input:    `{"\uffff": 1, "\uD800\uDC00": 2}`,
			expected: "{\"\U00010000\":2,\"\uffff\":1}", // Unescapes surrogate pair to UTF-8 and sorts first!
		},
		{
			name:     "Max Unicode U+10FFFF (D83F DFFF) vs U+FFFF",
			input:    "{\"\uffff\": \"bmp\", \"\U0010FFFF\": \"max\"}",
			expected: "{\"\U0010ffff\":\"max\",\"\uffff\":\"bmp\"}",
		},
		{
			name: "Multiple astral characters and BMP characters sorted by UTF-16 code units",
			// U+0061 'a' (0x0061)
			// U+007A 'z' (0x007A)
			// U+1D11E 𝄞 (0xD834, 0xDD1E)
			// U+1F600 😀 (0xD83D, 0xDE00)
			// U+1F680 🚀 (0xD83D, 0xDE80)
			// U+20000 𠀀 (0xD840, 0xDC00)
			// U+FFFF ￿ (0xFFFF)
			input:    `{"￿": 7, "🚀": 5, "a": 1, "𠀀": 6, "𝄞": 3, "z": 2, "😀": 4}`,
			expected: `{"a":1,"z":2,"𝄞":3,"😀":4,"🚀":5,"𠀀":6,"￿":7}`,
		},
		{
			name: "Astral surrogate pair tie-break on low surrogate",
			// 😀 U+1F600 (D83D DE00) vs 😁 U+1F601 (D83D DE01)
			input:    `{"😁": 2, "😀": 1}`,
			expected: `{"😀":1,"😁":2}`,
		},
		{
			name: "Prefix comparison with astral characters",
			// "𝄞" (len 2) vs "𝄞a" (len 3) vs "𝄞𝄞" (len 4)
			input:    `{"𝄞𝄞": 3, "𝄞a": 2, "𝄞": 1}`,
			expected: `{"𝄞":1,"𝄞a":2,"𝄞𝄞":3}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			canon, err := Canonicalize([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected canonicalize error: %v", err)
			}
			if string(canon) != tc.expected {
				t.Errorf("\nexpected: %s\ngot:      %s", tc.expected, string(canon))
			}
		})
	}
}

// TestAdversarial_ExtremeFloatRepresentations verifies ECMAScript/RFC 8785 number formatting.
func TestAdversarial_ExtremeFloatRepresentations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Zeroes
		{"positive zero", `{"n": 0}`, `{"n":0}`},
		{"negative zero float", `{"n": -0.0}`, `{"n":0}`},
		{"negative zero integer", `{"n": -0}`, `{"n":0}`},

		// Boundary at 1e21: 1e20 must be fixed notation (21 digits), 1e21 must be exponential (1e+21)
		{"1e20 fixed notation", `{"n": 100000000000000000000}`, `{"n":100000000000000000000}`},
		{"1e21 exponential notation", `{"n": 1e21}`, `{"n":1e+21}`},
		{"negative 1e21", `{"n": -1e21}`, `{"n":-1e+21}`},

		// Boundary at 1e-6: 1e-6 is 0.000001, 1e-7 is 1e-7
		{"1e-6 fixed notation", `{"n": 0.000001}`, `{"n":0.000001}`},
		{"1e-7 exponential notation", `{"n": 0.0000001}`, `{"n":1e-7}`},
		{"negative 1e-6", `{"n": -0.000001}`, `{"n":-0.000001}`},
		{"negative 1e-7", `{"n": -0.0000001}`, `{"n":-1e-7}`},

		// Large numbers
		{"max float64", fmt.Sprintf(`{"n": %s}`, strconvFormat(math.MaxFloat64)), fmt.Sprintf(`{"n":%s}`, formatECMAScriptNumber(math.MaxFloat64))},
		{"large exponent 1.234e+30", `{"n": 1.234e+30}`, `{"n":1.234e+30}`},

		// Subnormal numbers
		{"smallest nonzero float64 (5e-324)", fmt.Sprintf(`{"n": %s}`, strconvFormat(math.SmallestNonzeroFloat64)), `{"n":5e-324}`},

		// Integers as floats
		{"float with zero decimal", `{"n": 42.0}`, `{"n":42}`},
		{"float with many zero decimals", `{"n": 1000.000000}`, `{"n":1000}`},
		{"large integer 2^53 - 1", `{"n": 9007199254740991.0}`, `{"n":9007199254740991}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			canon, err := Canonicalize([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected canonicalize error: %v", err)
			}
			if string(canon) != tc.expected {
				t.Errorf("\nexpected: %s\ngot:      %s", tc.expected, string(canon))
			}
		})
	}
}

func strconvFormat(f float64) string {
	return formatECMAScriptNumber(f)
}

// TestAdversarial_VietnameseUnicodeDiacritics verifies that all Vietnamese characters
// remain unescaped raw UTF-8 bytes and are never converted to \uXXXX.
func TestAdversarial_VietnameseUnicodeDiacritics(t *testing.T) {
	vietnameseSample := `{"nghi_dinh":"130/2018/NĐ-CP","thong_tu":"06/2019/TT-BTTTT","tieu_chuan":"Chữ ký số & Xác thực điện tử","dia_chi":"Số 57 Huỳnh Thúc Kháng, Láng Hạ, Đống Đa, Hà Nội","nguoi_ky":"Nguyễn Trần Bảo Đắc"}`
	canon, err := Canonicalize([]byte(vietnameseSample))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	canonStr := string(canon)
	if strings.Contains(canonStr, `\u`) {
		t.Errorf("Vietnamese characters must NOT be escaped as \\uXXXX, got: %s", canonStr)
	}

	// Verify that escaped input gets normalized to raw UTF-8
	escapedInput := []byte(`{"name":"Nguy\u1ec5n V\u0103n \u0110\u1eafc"}`)
	canonEscaped, err := Canonicalize(escapedInput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedRaw := `{"name":"Nguyễn Văn Đắc"}`
	if string(canonEscaped) != expectedRaw {
		t.Errorf("expected escaped \\uXXXX to normalize to raw UTF-8: %s, got: %s", expectedRaw, string(canonEscaped))
	}

	// 1. Direct writeCanonicalValue/writeCanonicalString properly catches invalid UTF-8
	var buf bytes.Buffer
	err = writeCanonicalValue(&buf, "\xff\xfe")
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("writeCanonicalValue should return ErrInvalidUTF8 on invalid UTF-8, got: %v", err)
	}

	// 2. Canonicalize(jsonBytes) with raw invalid UTF-8 bytes:
	// Go's json.NewDecoder replaces invalid UTF-8 with U+FFFD instead of failing early,
	// so utf8.Valid(jsonBytes) is explicitly checked at the start of Canonicalize() per RFC 8785 Section 3.2.2.1.
	invalidJSON := []byte("{\"bad\":\"\xff\xfe\"}")
	_, err = Canonicalize(invalidJSON)
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("Canonicalize must reject invalid UTF-8 with ErrInvalidUTF8, got: %v", err)
	}
}

// TestAdversarial_ComplexNestedStructureReproducibility tests 10-level nested structures
// with randomized key permutations across 100 runs to guarantee SHA-256 byte-for-byte reproducibility.
func TestAdversarial_ComplexNestedStructureReproducibility(t *testing.T) {
	// 100 permutations of the same logical data with completely scrambled keys and whitespace
	var canonicalReference []byte
	var hashReference [32]byte

	for run := 0; run < 100; run++ {
		// Scramble keys and inject arbitrary whitespace
		inputJSON := generateRandomizedComplexJSON(run)
		canon, err := Canonicalize([]byte(inputJSON))
		if err != nil {
			t.Fatalf("run %d failed canonicalize: %v", run, err)
		}
		hash := sha256.Sum256(canon)

		if run == 0 {
			canonicalReference = canon
			hashReference = hash
		} else {
			if !bytes.Equal(canon, canonicalReference) {
				t.Fatalf("run %d produced non-reproducible canonical bytes:\nreference: %s\ncurrent:   %s", run, string(canonicalReference), string(canon))
			}
			if hash != hashReference {
				t.Fatalf("run %d produced hash mismatch: %x vs %x", run, hash, hashReference)
			}
		}
	}
}

func generateRandomizedComplexJSON(seed int) string {
	r := rand.New(rand.NewSource(int64(seed)))

	// Key-value pairs for level 1
	kvs := map[string]string{
		"decision_id":       `"dec-ai-98214"`,
		"ai_system_id":      `"credit-scoring-v2"`,
		"model_version":     `"xgboost-v2.1.0"`,
		"requires_approval": `true`,
		"score":             `785.5`,
		"zero_val":          `-0.0`,
		"large_int":         `500000000`,
		"tags":              `["vietnam","risk_high","banking"]`,
		"nested_eval": `{
			"tier": "TIER_1_HIGH_RISK",
			"rules_triggered": ["RULE_HIGH_AMOUNT", "RULE_CREDIT_BURDEN"],
			"sub_eval": {
				"shap_scores": {"income": 0.42, "debt_ratio": -0.31, "history": 0.15},
				"approvals": [
					{"role": "CREDIT_LEAD", "status": "APPROVED", "approver": "Nguyễn Văn Đắc"},
					{"role": "CRO_RISK_OFFICER", "status": "PENDING", "approver": null}
				]
			}
		}`,
	}

	keys := make([]string, 0, len(kvs))
	for k := range kvs {
		keys = append(keys, k)
	}
	r.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })

	var sb strings.Builder
	sb.WriteString("{\n")
	for i, k := range keys {
		// Add random whitespace
		ws := strings.Repeat(" ", r.Intn(4))
		sb.WriteString(fmt.Sprintf(`%s"%s": %s`, ws, k, kvs[k]))
		if i < len(keys)-1 {
			sb.WriteString(",\n")
		}
	}
	sb.WriteString("\n}")
	return sb.String()
}

// TestAdversarial_ArrayOrderPreserved confirms arrays preserve element order
// while objects inside array elements have their keys sorted.
func TestAdversarial_ArrayOrderPreserved(t *testing.T) {
	input := []byte(`[{"z":1,"a":2},{"c":3,"b":4}]`)
	expected := `[{"a":2,"z":1},{"b":4,"c":3}]`

	canon, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(canon) != expected {
		t.Errorf("expected: %s, got: %s", expected, string(canon))
	}
}

// TestAdversarial_EmptyAndNullStructures tests edge case literals: null, false, true, empty string, empty map, empty array.
func TestAdversarial_EmptyAndNullStructures(t *testing.T) {
	input := []byte(`{"a": {}, "b": [], "c": null, "d": "", "e": false, "f": true}`)
	expected := `{"a":{},"b":[],"c":null,"d":"","e":false,"f":true}`

	canon, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(canon) != expected {
		t.Errorf("expected: %s, got: %s", expected, string(canon))
	}
}

// TestAdversarial_HashSHA256HexIntegrity tests SHA-256 computation against known reference vectors.
func TestAdversarial_HashSHA256HexIntegrity(t *testing.T) {
	data := map[string]interface{}{
		"b": 2,
		"a": 1,
	}
	hexHash, canon, err := HashSHA256Hex(data)
	if err != nil {
		t.Fatalf("HashSHA256Hex error: %v", err)
	}
	if string(canon) != `{"a":1,"b":2}` {
		t.Errorf("expected canonical `{\"a\":1,\"b\":2}`, got %s", string(canon))
	}
	expectedHash := sha256.Sum256([]byte(`{"a":1,"b":2}`))
	if hexHash != hex.EncodeToString(expectedHash[:]) {
		t.Errorf("hash mismatch: expected %x, got %s", expectedHash, hexHash)
	}
}
