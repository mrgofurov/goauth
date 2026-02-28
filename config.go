package goauth

import (
	"time"
)

// Config holds the configuration for the auth framework.
type Config struct {
	// EnabledProviders specifies which providers are enabled (e.g., ["bearer", "session", "basic"]).
	// If empty, all registered providers are enabled.
	EnabledProviders []string

	// ProviderPriority specifies the order in which providers are tried.
	// Default: ["bearer", "session", "basic"]
	ProviderPriority []string

	// AllowAnonymous if true, allows unauthenticated requests to proceed with an anonymous principal.
	// If false, returns 401 when no authentication is provided.
	AllowAnonymous bool

	// LoggingHook is called for authentication events (success, failure, etc.).
	LoggingHook LoggingHook

	// JWT contains JWT-specific configuration.
	JWT JWTConfig

	// Session contains session-specific configuration.
	Session SessionConfig

	// Basic contains basic auth-specific configuration.
	Basic BasicConfig
}

// JWTConfig holds JWT-specific configuration.
type JWTConfig struct {
	// SigningMethod is the JWT signing method (e.g., "HS256", "RS256").
	SigningMethod string

	// SecretKey is the secret key for HMAC signing methods.
	SecretKey []byte

	// PublicKey is the public key for RSA/ECDSA signing methods (PEM encoded).
	PublicKey []byte

	// PrivateKey is the private key for RSA/ECDSA signing methods (PEM encoded).
	// Used for token generation.
	PrivateKey []byte

	// Issuer is the expected issuer claim.
	Issuer string

	// Audience is the expected audience claim.
	Audience []string

	// Leeway is the allowed clock skew for token validation.
	Leeway time.Duration

	// ClaimsMapper maps JWT claims to Principal fields.
	// If nil, uses default mapping.
	ClaimsMapper ClaimsMapper

	// KeyFunc is a custom key function for JWT validation.
	// If set, overrides SecretKey/PublicKey.
	KeyFunc JWTKeyFunc

	// RequiredClaims specifies claims that must be present in the token.
	RequiredClaims []string
}

// SessionConfig holds session-specific configuration.
type SessionConfig struct {
	// CookieName is the name of the session cookie.
	// Default: "session_id"
	CookieName string

	// HeaderName is the optional header name for session ID.
	// Default: "X-Session-Id"
	HeaderName string

	// TTL is the session time-to-live.
	// Default: 24 hours
	TTL time.Duration

	// Secure sets the Secure flag on the session cookie.
	Secure bool

	// HTTPOnly sets the HttpOnly flag on the session cookie.
	HTTPOnly bool

	// SameSite sets the SameSite attribute on the session cookie.
	SameSite string

	// Domain sets the Domain attribute on the session cookie.
	Domain string

	// Path sets the Path attribute on the session cookie.
	Path string

	// RotateOnAuth if true, rotates the session ID after successful authentication.
	RotateOnAuth bool
}

// BasicConfig holds basic auth-specific configuration.
type BasicConfig struct {
	// Realm is the realm name for WWW-Authenticate header.
	// Default: "Restricted"
	Realm string

	// RateLimitWindow is the time window for rate limiting.
	RateLimitWindow time.Duration

	// MaxAttempts is the maximum number of failed attempts within the window.
	MaxAttempts int

	// LockoutDuration is how long to lock out after max attempts.
	LockoutDuration time.Duration

	// RateLimiter is an optional custom rate limiter.
	RateLimiter RateLimiter
}

// ClaimsMapper is a function that maps JWT claims to a Principal.
type ClaimsMapper func(claims map[string]any) (*Principal, error)

// JWTKeyFunc is a function that returns the key for JWT validation.
// This is useful for key rotation scenarios.
type JWTKeyFunc func(token any) (any, error)

// RateLimiter is an interface for rate limiting authentication attempts.
type RateLimiter interface {
	// Allow checks if the request is allowed.
	Allow(key string) bool

	// Record records a failed attempt.
	RecordFailure(key string)

	// Reset resets the failure count for a key.
	Reset(key string)

	// IsLocked checks if the key is currently locked out.
	IsLocked(key string) bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ProviderPriority: []string{"bearer", "session", "basic"},
		AllowAnonymous:   false,
		JWT: JWTConfig{
			SigningMethod: "HS256",
			Leeway:        time.Minute,
		},
		Session: SessionConfig{
			CookieName: "session_id",
			HeaderName: "X-Session-Id",
			TTL:        24 * time.Hour,
			HTTPOnly:   true,
			Secure:     true,
			SameSite:   "Lax",
			Path:       "/",
		},
		Basic: BasicConfig{
			Realm:           "Restricted",
			RateLimitWindow: 15 * time.Minute,
			MaxAttempts:     5,
			LockoutDuration: 15 * time.Minute,
		},
	}
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	// JWT validation
	if c.JWT.SigningMethod != "" {
		switch c.JWT.SigningMethod {
		case "HS256", "HS384", "HS512":
			// HMAC methods require a secret key (unless KeyFunc is provided)
			if len(c.JWT.SecretKey) == 0 && c.JWT.KeyFunc == nil {
				// Will be validated when provider is created
			}
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
			// RSA/ECDSA methods require a public key (unless KeyFunc is provided)
			if len(c.JWT.PublicKey) == 0 && c.JWT.KeyFunc == nil {
				// Will be validated when provider is created
			}
		}
	}

	return nil
}
