package goauth

import (
	"net/http"
)

// Authenticator is the interface that all authentication providers must implement.
type Authenticator interface {
	// Name returns the unique name of this authenticator (e.g., "bearer", "basic", "session").
	Name() string

	// Authenticate attempts to authenticate the request and returns a Principal if successful.
	// Returns nil, nil if authentication is not applicable (e.g., no credentials present).
	// Returns nil, error if authentication failed.
	Authenticate(r *http.Request) (*Principal, error)

	// Supports checks if this authenticator can handle the given request.
	// This is used to determine which authenticator to try first.
	Supports(r *http.Request) bool
}

// AuthResult represents the result of an authentication attempt.
type AuthResult struct {
	// Principal is the authenticated user, or nil if not authenticated.
	Principal *Principal

	// Provider is the name of the provider that authenticated the user.
	Provider string

	// Error is the authentication error, if any.
	Error error
}

// Success returns true if authentication was successful.
func (r *AuthResult) Success() bool {
	return r.Principal != nil && r.Principal.Authenticated && r.Error == nil
}

// NewAuthResult creates a new successful AuthResult.
func NewAuthResult(principal *Principal, provider string) *AuthResult {
	return &AuthResult{
		Principal: principal,
		Provider:  provider,
	}
}

// NewAuthFailure creates a new failed AuthResult.
func NewAuthFailure(provider string, err error) *AuthResult {
	return &AuthResult{
		Provider: provider,
		Error:    err,
	}
}

// TokenExtractor is a function type for extracting tokens from requests.
type TokenExtractor func(r *http.Request) string

// CredentialVerifier is a function type for verifying username/password credentials.
// Returns the Principal if credentials are valid, or an error if invalid.
type CredentialVerifier func(username, password string) (*Principal, error)

// TokenValidator is a function type for validating opaque tokens.
// Returns the Principal if the token is valid, or an error if invalid.
type TokenValidator func(token string) (*Principal, error)

// AuthEventType represents the type of authentication event.
type AuthEventType string

const (
	AuthEventSuccess  AuthEventType = "success"
	AuthEventFailure  AuthEventType = "failure"
	AuthEventExpired  AuthEventType = "expired"
	AuthEventRejected AuthEventType = "rejected"
)

// AuthEvent represents an authentication event for logging/auditing.
type AuthEvent struct {
	Type      AuthEventType
	Provider  string
	UserID    string
	IP        string
	UserAgent string
	Error     error
	Metadata  map[string]any
}

// LoggingHook is a function type for logging authentication events.
type LoggingHook func(event AuthEvent)
