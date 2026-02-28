package providers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goauth"
)

func TestSessionProvider_Name(t *testing.T) {
	p := NewSessionProvider()
	if p.Name() != "session" {
		t.Errorf("expected 'session', got '%s'", p.Name())
	}
}

func TestSessionProvider_Supports(t *testing.T) {
	p := NewSessionProvider()

	tests := []struct {
		name     string
		cookie   string
		header   string
		expected bool
	}{
		{"with cookie", "session123", "", true},
		{"with header", "", "session123", true},
		{"no session", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "session_id", Value: tt.cookie})
			}
			if tt.header != "" {
				req.Header.Set("X-Session-Id", tt.header)
			}
			if got := p.Supports(req); got != tt.expected {
				t.Errorf("Supports() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSessionProvider_Authenticate_Valid(t *testing.T) {
	store := NewMemorySessionStore()
	p := NewSessionProvider(WithSessionStore(store))

	// Create a session
	principal := goauth.NewPrincipal("user123").WithRoles("user")
	session, _ := p.CreateSession(principal)

	// Test authentication
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: session.ID})

	authenticated, err := p.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if authenticated == nil {
		t.Fatal("expected principal")
	}
	if authenticated.ID != "user123" {
		t.Errorf("expected ID 'user123', got '%s'", authenticated.ID)
	}
}

func TestSessionProvider_Authenticate_Invalid(t *testing.T) {
	p := NewSessionProvider()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: "nonexistent"})

	_, err := p.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for invalid session")
	}

	authErr := goauth.GetAuthError(err)
	if authErr == nil || authErr.Code != goauth.ErrCodeSessionInvalid {
		t.Errorf("expected SESSION_INVALID error, got %v", err)
	}
}

func TestSessionProvider_Authenticate_Expired(t *testing.T) {
	store := NewMemorySessionStore()
	p := NewSessionProvider(
		WithSessionStore(store),
		WithSessionTTL(-time.Hour), // Already expired
	)

	principal := goauth.NewPrincipal("user123")
	session, _ := p.CreateSession(principal)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: session.ID})

	_, err := p.Authenticate(req)
	if err == nil {
		t.Fatal("expected error for expired session")
	}

	authErr := goauth.GetAuthError(err)
	if authErr == nil || authErr.Code != goauth.ErrCodeAuthExpired {
		t.Errorf("expected AUTH_EXPIRED error, got %v", err)
	}
}

func TestSessionProvider_CreateAndDestroy(t *testing.T) {
	store := NewMemorySessionStore()
	p := NewSessionProvider(WithSessionStore(store))

	principal := goauth.NewPrincipal("user123").WithRoles("admin")
	session, err := p.CreateSession(principal)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if session.ID == "" {
		t.Error("session ID should not be empty")
	}
	if store.Count() != 1 {
		t.Errorf("expected 1 session, got %d", store.Count())
	}

	// Destroy session
	err = p.DestroySession(session.ID)
	if err != nil {
		t.Fatalf("failed to destroy session: %v", err)
	}
	if store.Count() != 0 {
		t.Errorf("expected 0 sessions, got %d", store.Count())
	}
}

func TestSessionProvider_Rotate(t *testing.T) {
	store := NewMemorySessionStore()
	p := NewSessionProvider(WithSessionStore(store))

	principal := goauth.NewPrincipal("user123").WithRoles("user")
	session, _ := p.CreateSession(principal)
	oldID := session.ID

	// Rotate session
	newSession, err := p.RotateSession(oldID)
	if err != nil {
		t.Fatalf("failed to rotate session: %v", err)
	}
	if newSession.ID == oldID {
		t.Error("new session ID should be different")
	}
	if newSession.UserID != "user123" {
		t.Error("user ID should be preserved")
	}

	// Old session should be deleted
	oldSession, _ := store.Get(oldID)
	if oldSession != nil {
		t.Error("old session should be deleted")
	}

	// New session should exist
	existingSession, _ := store.Get(newSession.ID)
	if existingSession == nil {
		t.Error("new session should exist")
	}
}

func TestMemorySessionStore_Cleanup(t *testing.T) {
	store := NewMemorySessionStore()

	// Create expired session directly
	expiredSession := &Session{
		ID:        "expired-session",
		UserID:    "user",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	store.Set(expiredSession)

	// Create valid session
	validSession := &Session{
		ID:        "valid-session",
		UserID:    "user",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	store.Set(validSession)

	if store.Count() != 2 {
		t.Errorf("expected 2 sessions, got %d", store.Count())
	}

	// Cleanup
	store.Cleanup()

	if store.Count() != 1 {
		t.Errorf("expected 1 session after cleanup, got %d", store.Count())
	}

	remaining, _ := store.Get("valid-session")
	if remaining == nil {
		t.Error("valid session should remain")
	}
}
