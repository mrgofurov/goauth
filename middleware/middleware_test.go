package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goauth"
	"github.com/goauth/providers"
	"github.com/golang-jwt/jwt/v5"
)

func TestAuthMiddleware_BearerSuccess(t *testing.T) {
	secret := []byte("test-secret")
	bearer := providers.NewBearerProvider(providers.WithSecretKey(secret))
	m := NewAuthMiddleware(WithProviders(bearer))

	// Create valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(secret)

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := PrincipalFromRequest(r)
		if principal == nil {
			t.Error("expected principal in context")
			w.WriteHeader(500)
			return
		}
		if principal.ID != "user123" {
			t.Errorf("expected ID 'user123', got '%s'", principal.ID)
		}
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_NoAuth(t *testing.T) {
	m := NewAuthMiddleware(WithConfig(goauth.Config{AllowAnonymous: false}))

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestAuthMiddleware_AllowAnonymous(t *testing.T) {
	m := NewAuthMiddleware(WithConfig(goauth.Config{AllowAnonymous: true}))

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := PrincipalFromRequest(r)
		if principal == nil {
			t.Error("expected anonymous principal")
			w.WriteHeader(500)
			return
		}
		if principal.Authenticated {
			t.Error("expected unauthenticated principal")
		}
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_ProviderPriority(t *testing.T) {
	secret := []byte("test-secret")
	bearer := providers.NewBearerProvider(providers.WithSecretKey(secret))
	basic := providers.NewBasicProvider(
		providers.WithCredentialVerifier(func(u, p string) (*goauth.Principal, error) {
			return goauth.NewPrincipal("basic-user"), nil
		}),
	)

	m := NewAuthMiddleware(
		WithProviders(bearer, basic),
		WithConfig(goauth.Config{
			ProviderPriority: []string{"bearer", "basic"},
		}),
	)

	// Create valid JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "jwt-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(secret)

	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := PrincipalFromRequest(r)
		// When both are present, bearer should win due to priority
		if principal.ID != "jwt-user" {
			t.Errorf("expected 'jwt-user', got '%s'", principal.ID)
		}
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	// Also set basic auth (should be ignored)
	basicCreds := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	req.Header.Add("Authorization", "Basic "+basicCreds)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
}

func TestPrincipalFromContext(t *testing.T) {
	principal := goauth.NewPrincipal("test-user").WithRoles("admin")
	ctx := SetPrincipal(context.Background(), principal)

	retrieved := PrincipalFromContext(ctx)
	if retrieved == nil {
		t.Fatal("expected principal from context")
	}
	if retrieved.ID != "test-user" {
		t.Errorf("expected ID 'test-user', got '%s'", retrieved.ID)
	}
}

func TestPrincipalFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	principal := PrincipalFromContext(ctx)
	if principal != nil {
		t.Error("expected nil principal from empty context")
	}
}
