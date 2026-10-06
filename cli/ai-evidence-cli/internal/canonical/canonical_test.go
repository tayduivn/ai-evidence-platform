package canonical

import (
	"math"
	"testing"
)

func TestCanonical_KeySortingLexicographical(t *testing.T) {
	input := []byte(`{"z": 1, "a": 2, "m": {"b": 3, "a": 4}}`)
	expected := `{"a":2,"m":{"a":4,"b":3},"z":1}`

	canon, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(canon) != expected {
		t.Errorf("expected %s, got %s", expected, string(canon))
	}
}

func TestCanonical_AstralPlaneKeySorting(t *testing.T) {
	// Astral symbols: U+1D11E (MUSICAL SYMBOL G CLEF) -> UTF-16 surrogate pair
	input := []byte(`{"𝄞": 1, "z": 2, "a": 3}`)
	canon, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 'a' (U+0061) < 'z' (U+007A) < '𝄞' (U+1D11E encoded as D834 DD1E)
	expected := `{"a":3,"z":2,"𝄞":1}`
	if string(canon) != expected {
		t.Errorf("expected %s, got %s", expected, string(canon))
	}
}

func TestCanonical_VietnameseUnicodeFidelity(t *testing.T) {
	input := []byte(`{"approver":"Nguyễn Văn Đắc","city":"TP. Hồ Chí Minh","province":"Đắk Lắk"}`)
	canon, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Must preserve raw UTF-8 multibyte characters without \uXXXX escaping
	expected := `{"approver":"Nguyễn Văn Đắc","city":"TP. Hồ Chí Minh","province":"Đắk Lắk"}`
	if string(canon) != expected {
		t.Errorf("expected %s, got %s", expected, string(canon))
	}
}

func TestCanonical_NumberFormatting(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"integer float", `{"num": 100.0}`, `{"num":100}`},
		{"zero", `{"num": 0.0}`, `{"num":0}`},
		{"negative zero", `{"num": -0.0}`, `{"num":0}`},
		{"decimal float", `{"num": 785.5}`, `{"num":785.5}`},
		{"small positive", `{"num": 0.000001}`, `{"num":0.000001}`},
		{"exponential small", `{"num": 0.0000001}`, `{"num":1e-7}`},
		{"exponential large", `{"num": 1e21}`, `{"num":1e+21}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			canon, err := Canonicalize([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(canon) != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, string(canon))
			}
		})
	}
}

func TestCanonical_HTMLSpecialCharsNotEscaped(t *testing.T) {
	input := []byte(`{"prompt":"<xml>&test</xml>"}`)
	canon, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := `{"prompt":"<xml>&test</xml>"}`
	if string(canon) != expected {
		t.Errorf("expected %s, got %s", expected, string(canon))
	}
}

func TestCanonical_EscapeControlCharacters(t *testing.T) {
	input := []byte("{\"text\":\"line1\\nline2\\ttab\\u0000null\"}")
	canon, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := `{"text":"line1\nline2\ttab\u0000null"}`
	if string(canon) != expected {
		t.Errorf("expected %s, got %s", expected, string(canon))
	}
}

func TestCanonical_RejectNaNAndInf(t *testing.T) {
	_, err := Marshal(math.NaN())
	if err == nil {
		t.Errorf("expected error for NaN, got nil")
	}

	_, err = Marshal(math.Inf(1))
	if err == nil {
		t.Errorf("expected error for Inf, got nil")
	}
}

func TestCanonical_HashSHA256(t *testing.T) {
	payload := DecisionSignPayload{
		DecisionID:       "dec-001",
		ApproverID:       "user-001",
		Action:           "APPROVE",
		DwellTimeSeconds: 15,
		Timestamp:        "2026-10-05T10:00:00Z",
	}
	digest, canon, err := HashSHA256(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(digest) != 32 {
		t.Errorf("expected 32-byte digest, got %d", len(digest))
	}
	expectedCanon := `{"action":"APPROVE","approver_id":"user-001","decision_id":"dec-001","dwell_time_seconds":15,"timestamp":"2026-10-05T10:00:00Z"}`
	if string(canon) != expectedCanon {
		t.Errorf("expected canonical %s, got %s", expectedCanon, string(canon))
	}
}
