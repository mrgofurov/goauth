package providers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goauth"
	"github.com/golang-jwt/jwt/v5"
)

func TestBearerProvider_Name(t *testing.T) {
	p := NewBearerProvider()
	if p.Name() != "bearer" {
		t.Errorf("expected 'bearer', got '%s'", p.Name())
	}
}

func TestBearerProvider_Supports(t *testing.T) {
	p := NewBearerProvider()

	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{"valid bearer", "Bearer token123", true},
		{"lowercase bearer", "bearer token123", true},
		{"basic auth", "Basic dXNlcjpwYXNz", false},
		{"empty", "", false},
		{"invalid format", "Token abc", false},
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

func TestBearerProvider_JWT_Valid(t *testing.T) {
	secret := []byte("test-secret-key")
	p := NewBearerProvider(WithSecretKey(secret))

	// Create a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "user123",
		"roles": []string{"admin", "user"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(secret)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	principal, err := p.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal == nil {
		t.Fatal("expected principal, got nil")
	}
	if principal.ID != "user123" {
		t.Errorf("expected ID 'user123', got '%s'", principal.ID)
	}
	if !principal.HasRole("admin") {
		t.Error("expected to have admin role")
	}
}

func TestBearerProvider_JWT_Expired(t *testing.T) {
	secret := []byte("test-secret-key")
	p := NewBearerProvider(WithSecretKey(secret))

	// Create an expired token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired
	})
	tokenString, _ := token.SignedString(secret)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, err := p.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for expired token")
	}

	authErr := goauth.GetAuthError(err)
	if authErr == nil || authErr.Code != goauth.ErrCodeAuthExpired {
		t.Errorf("expected AUTH_EXPIRED error, got %v", err)
	}
}

func TestBearerProvider_JWT_Invalid(t *testing.T) {
	secret := []byte("test-secret-key")
	p := NewBearerProvider(WithSecretKey(secret))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	_, err := p.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestBearerProvider_NoToken(t *testing.T) {
	p := NewBearerProvider(WithSecretKey([]byte("secret")))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	principal, err := p.Authenticate(req)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != nil {
		t.Error("expected nil principal when no token")
	}
}

func TestBearerProvider_OpaqueToken(t *testing.T) {
	verifier := func(token string) (*goauth.Principal, error) {
		if token == "valid-opaque-token" {
			return goauth.NewPrincipal("opaque-user").WithRoles("user"), nil
		}
		return nil, goauth.ErrAuthInvalid
	}

	p := NewBearerProvider(WithOpaqueVerifier(verifier))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-opaque-token")

	principal, err := p.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal == nil || principal.ID != "opaque-user" {
		t.Error("expected opaque-user principal")
	}
}
