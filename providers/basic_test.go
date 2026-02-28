package providers

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goauth"
)

func TestBasicProvider_Name(t *testing.T) {
	p := NewBasicProvider()
	if p.Name() != "basic" {
		t.Errorf("expected 'basic', got '%s'", p.Name())
	}
}

func TestBasicProvider_Supports(t *testing.T) {
	p := NewBasicProvider()

	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{"valid basic", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")), true},
		{"lowercase basic", "basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")), true},
		{"bearer auth", "Bearer token123", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			if got := p.Supports(req); got != tt.expected {
				t.Errorf("Supports() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBasicProvider_ValidCredentials(t *testing.T) {
	verifier := func(username, password string) (*goauth.Principal, error) {
		if username == "admin" && password == "secret" {
			return goauth.NewPrincipal("admin").WithRoles("admin"), nil
		}
		return nil, goauth.ErrBasicInvalid
	}

	p := NewBasicProvider(WithCredentialVerifier(verifier))

	credentials := base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic "+credentials)

	principal, err := p.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal == nil {
		t.Fatal("expected principal")
	}
	if principal.ID != "admin" {
		t.Errorf("expected ID 'admin', got '%s'", principal.ID)
	}
}

func TestBasicProvider_InvalidCredentials(t *testing.T) {
	verifier := func(username, password string) (*goauth.Principal, error) {
		return nil, goauth.ErrBasicInvalid
	}

	p := NewBasicProvider(WithCredentialVerifier(verifier))

	credentials := base64.StdEncoding.EncodeToString([]byte("wrong:credentials"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic "+credentials)

	_, err := p.Authenticate(req)
	if err == nil {
		t.Fatal("expected error")
	}

	authErr := goauth.GetAuthError(err)
	if authErr == nil || authErr.Code != goauth.ErrCodeBasicInvalid {
		t.Errorf("expected BASIC_INVALID error, got %v", err)
	}
}

func TestBasicProvider_NoCredentials(t *testing.T) {
	p := NewBasicProvider()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	principal, err := p.Authenticate(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != nil {
		t.Error("expected nil principal when no credentials")
	}
}

func TestBasicProvider_InvalidBase64(t *testing.T) {
	verifier := func(username, password string) (*goauth.Principal, error) {
		return goauth.NewPrincipal(username), nil
	}

	p := NewBasicProvider(WithCredentialVerifier(verifier))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic not-valid-base64!!!")

	principal, err := p.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != nil {
		t.Error("expected nil principal for invalid base64")
	}
}

func TestBasicProvider_Realm(t *testing.T) {
	p := NewBasicProvider(WithRealm("MyApp"))
	if p.Realm() != "MyApp" {
		t.Errorf("expected realm 'MyApp', got '%s'", p.Realm())
	}
}

func TestConstantTimeCompare(t *testing.T) {
	tests := []struct {
		a, b     string
		expected bool
	}{
		{"password", "password", true},
		{"password", "Password", false},
		{"password", "passwor", false},
		{"", "", true},
	}

	for _, tt := range tests {
		if got := ConstantTimeCompare(tt.a, tt.b); got != tt.expected {
			t.Errorf("ConstantTimeCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
		}
	}
}
