package security

import (
	"testing"
)

func TestConstantTimeCompare(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"password", "password", true},
		{"password", "Password", false},
		{"password", "passwor", false},
		{"", "", true},
		{"a", "b", false},
	}

	for _, tt := range tests {
		if got := ConstantTimeCompare(tt.a, tt.b); got != tt.expected {
			t.Errorf("ConstantTimeCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
		}
	}
}

func TestGenerateSecureToken(t *testing.T) {
	token1, err := GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token1) == 0 {
		t.Error("expected non-empty token")
	}

	token2, _ := GenerateSecureToken(32)
	if token1 == token2 {
		t.Error("tokens should be unique")
	}
}

func TestGenerateSecureTokenHex(t *testing.T) {
	token, err := GenerateSecureTokenHex(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("expected 32 chars, got %d", len(token))
	}
}

func TestHashPassword(t *testing.T) {
	password := "mysecretpassword"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == password {
		t.Error("hash should not equal plaintext")
	}
	if hash == "" {
		t.Error("hash should not be empty")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "mysecretpassword"
	hash, _ := HashPassword(password)

	if !VerifyPassword(hash, password) {
		t.Error("correct password should verify")
	}
	if VerifyPassword(hash, "wrongpassword") {
		t.Error("wrong password should not verify")
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		input    string
		visible  int
		expected string
	}{
		{"secrettoken123456", 4, "secr***3456"},
		{"short", 4, "***"},
		{"ab", 4, "***"},
	}

	for _, tt := range tests {
		got := SanitizeForLog(tt.input, tt.visible)
		if got != tt.expected {
			t.Errorf("SanitizeForLog(%q, %d) = %q, want %q", tt.input, tt.visible, got, tt.expected)
		}
	}
}

func TestMaskToken(t *testing.T) {
	tests := []struct {
		token    string
		expected string
	}{
		{"1234567890123456", "1234...3456"},
		{"short", "***"},
		{"12345678", "***"},
	}

	for _, tt := range tests {
		got := MaskToken(tt.token)
		if got != tt.expected {
			t.Errorf("MaskToken(%q) = %q, want %q", tt.token, got, tt.expected)
		}
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	bytes1, err := GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bytes1) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(bytes1))
	}

	bytes2, _ := GenerateRandomBytes(16)
	equal := true
	for i := range bytes1 {
		if bytes1[i] != bytes2[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Error("random bytes should be unique")
	}
}
