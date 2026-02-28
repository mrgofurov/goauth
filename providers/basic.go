package providers

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/goauth"
)

// BasicProvider implements HTTP Basic authentication.
type BasicProvider struct {
	verifier    goauth.CredentialVerifier
	realm       string
	rateLimiter goauth.RateLimiter
}

// BasicOption is a functional option for configuring BasicProvider.
type BasicOption func(*BasicProvider)

// WithCredentialVerifier sets the credential verification function.
func WithCredentialVerifier(verifier goauth.CredentialVerifier) BasicOption {
	return func(p *BasicProvider) {
		p.verifier = verifier
	}
}

// WithRealm sets the realm for WWW-Authenticate header.
func WithRealm(realm string) BasicOption {
	return func(p *BasicProvider) {
		p.realm = realm
	}
}

// WithRateLimiter sets a rate limiter for brute-force protection.
func WithRateLimiter(limiter goauth.RateLimiter) BasicOption {
	return func(p *BasicProvider) {
		p.rateLimiter = limiter
	}
}

// NewBasicProvider creates a new BasicProvider with the given options.
func NewBasicProvider(opts ...BasicOption) *BasicProvider {
	p := &BasicProvider{
		realm: "Restricted",
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// Name returns the provider name.
func (p *BasicProvider) Name() string {
	return "basic"
}

// Supports checks if the request has Basic authentication.
func (p *BasicProvider) Supports(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return strings.HasPrefix(strings.ToLower(auth), "basic ")
}

// Authenticate validates the basic auth credentials and returns the Principal.
func (p *BasicProvider) Authenticate(r *http.Request) (*goauth.Principal, error) {
	username, password, ok := p.extractCredentials(r)
	if !ok {
		return nil, nil // No credentials present, skip this provider
	}

	// Check rate limiting if configured
	if p.rateLimiter != nil {
		clientKey := getClientKey(r)
		if p.rateLimiter.IsLocked(clientKey) {
			return nil, goauth.NewAuthError(
				goauth.ErrCodeAuthInvalid,
				"Too many failed attempts. Please try again later.",
				http.StatusTooManyRequests,
			)
		}
	}

	// Verify credentials
	if p.verifier == nil {
		return nil, goauth.ErrInternal
	}

	principal, err := p.verifier(username, password)
	if err != nil || principal == nil {
		// Record failure for rate limiting
		if p.rateLimiter != nil {
			clientKey := getClientKey(r)
			p.rateLimiter.RecordFailure(clientKey)
		}
		return nil, goauth.ErrBasicInvalid
	}

	// Reset rate limiter on success
	if p.rateLimiter != nil {
		clientKey := getClientKey(r)
		p.rateLimiter.Reset(clientKey)
	}

	return principal, nil
}

// extractCredentials extracts username and password from the Authorization header.
func (p *BasicProvider) extractCredentials(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", false
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "basic") {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return "", "", false
	}

	return credentials[0], credentials[1], true
}

// Realm returns the configured realm for WWW-Authenticate header.
func (p *BasicProvider) Realm() string {
	return p.realm
}

// getClientKey returns a key for rate limiting based on the client's identity.
func getClientKey(r *http.Request) string {
	// Use X-Forwarded-For if behind a proxy, otherwise use RemoteAddr
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Strip port from RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return addr[:idx]
	}
	return addr
}

// ConstantTimeCompare performs a constant-time comparison of two strings.
// This helps prevent timing attacks.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SimpleCredentialStore is a simple in-memory credential store for testing/demo purposes.
// In production, use a database or LDAP verifier.
type SimpleCredentialStore struct {
	users map[string]userRecord
}

type userRecord struct {
	passwordHash string
	roles        []string
}

// NewSimpleCredentialStore creates a new SimpleCredentialStore.
func NewSimpleCredentialStore() *SimpleCredentialStore {
	return &SimpleCredentialStore{
		users: make(map[string]userRecord),
	}
}

// AddUser adds a user to the store.
// Password should be pre-hashed using bcrypt or similar.
func (s *SimpleCredentialStore) AddUser(username, passwordHash string, roles ...string) {
	s.users[username] = userRecord{
		passwordHash: passwordHash,
		roles:        roles,
	}
}

// Verify implements the CredentialVerifier interface.
// Note: This uses constant-time comparison but expects the password to be checked elsewhere.
func (s *SimpleCredentialStore) Verify(username, password string) (*goauth.Principal, error) {
	user, exists := s.users[username]
	if !exists {
		return nil, goauth.ErrBasicInvalid
	}

	// In production, use bcrypt.CompareHashAndPassword
	// This is a simplified version for demonstration
	if !ConstantTimeCompare(user.passwordHash, password) {
		return nil, goauth.ErrBasicInvalid
	}

	principal := goauth.NewPrincipal(username)
	principal.WithRoles(user.roles...)
	return principal, nil
}
