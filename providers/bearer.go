// Package providers contains authentication provider implementations.
package providers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/goauth"
	"github.com/golang-jwt/jwt/v5"
)

// BearerProvider implements bearer token authentication (JWT and opaque tokens).
type BearerProvider struct {
	config         goauth.JWTConfig
	opaqueVerifier goauth.TokenValidator
	secretKey      []byte
	publicKey      *rsa.PublicKey
	keyFunc        jwt.Keyfunc
}

// BearerOption is a functional option for configuring BearerProvider.
type BearerOption func(*BearerProvider)

// WithSecretKey sets the HMAC secret key for JWT validation.
func WithSecretKey(key []byte) BearerOption {
	return func(p *BearerProvider) {
		p.secretKey = key
	}
}

// WithPublicKey sets the RSA public key for JWT validation.
func WithPublicKey(key *rsa.PublicKey) BearerOption {
	return func(p *BearerProvider) {
		p.publicKey = key
	}
}

// WithPublicKeyPEM sets the RSA public key from PEM bytes.
func WithPublicKeyPEM(pemBytes []byte) BearerOption {
	return func(p *BearerProvider) {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return
		}
		if rsaKey, ok := pub.(*rsa.PublicKey); ok {
			p.publicKey = rsaKey
		}
	}
}

// WithKeyFunc sets a custom key function for JWT validation (supports key rotation).
func WithKeyFunc(fn jwt.Keyfunc) BearerOption {
	return func(p *BearerProvider) {
		p.keyFunc = fn
	}
}

// WithOpaqueVerifier sets a function for validating opaque (non-JWT) tokens.
func WithOpaqueVerifier(verifier goauth.TokenValidator) BearerOption {
	return func(p *BearerProvider) {
		p.opaqueVerifier = verifier
	}
}

// WithJWTConfig sets the full JWT configuration.
func WithJWTConfig(config goauth.JWTConfig) BearerOption {
	return func(p *BearerProvider) {
		p.config = config
	}
}

// NewBearerProvider creates a new BearerProvider with the given options.
func NewBearerProvider(opts ...BearerOption) *BearerProvider {
	p := &BearerProvider{
		config: goauth.JWTConfig{
			SigningMethod: "HS256",
			Leeway:        time.Minute,
		},
	}

	for _, opt := range opts {
		opt(p)
	}

	// Set up key function if not provided
	if p.keyFunc == nil {
		p.keyFunc = p.defaultKeyFunc
	}

	return p
}

// Name returns the provider name.
func (p *BearerProvider) Name() string {
	return "bearer"
}

// Supports checks if the request has a Bearer token.
func (p *BearerProvider) Supports(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	return strings.HasPrefix(strings.ToLower(auth), "bearer ")
}

// Authenticate validates the bearer token and returns the Principal.
func (p *BearerProvider) Authenticate(r *http.Request) (*goauth.Principal, error) {
	token := p.extractToken(r)
	if token == "" {
		return nil, nil // No token present, skip this provider
	}

	// Try JWT validation first
	principal, err := p.validateJWT(token)
	if err == nil && principal != nil {
		return principal, nil
	}

	// If JWT validation failed and we have an opaque verifier, try that
	if p.opaqueVerifier != nil {
		return p.opaqueVerifier(token)
	}

	// Return the JWT error if no opaque verifier
	if err != nil {
		return nil, err
	}

	return nil, goauth.ErrAuthInvalid
}

// extractToken extracts the bearer token from the Authorization header.
func (p *BearerProvider) extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

// validateJWT validates a JWT token and returns the Principal.
func (p *BearerProvider) validateJWT(tokenString string) (*goauth.Principal, error) {
	// Parse and validate the token
	token, err := jwt.Parse(tokenString, p.keyFunc, jwt.WithLeeway(p.config.Leeway))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, goauth.ErrAuthExpired
		}
		return nil, goauth.ErrAuthInvalid
	}

	if !token.Valid {
		return nil, goauth.ErrAuthInvalid
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, goauth.ErrAuthInvalid
	}

	// Validate issuer if configured
	if p.config.Issuer != "" {
		iss, _ := claims.GetIssuer()
		if iss != p.config.Issuer {
			return nil, goauth.NewAuthError(goauth.ErrCodeAuthInvalid, "invalid issuer", http.StatusUnauthorized)
		}
	}

	// Validate audience if configured
	if len(p.config.Audience) > 0 {
		aud, _ := claims.GetAudience()
		if !containsAny(aud, p.config.Audience) {
			return nil, goauth.NewAuthError(goauth.ErrCodeAuthInvalid, "invalid audience", http.StatusUnauthorized)
		}
	}

	// Use custom claims mapper if provided
	if p.config.ClaimsMapper != nil {
		return p.config.ClaimsMapper(claims)
	}

	// Default claims mapping
	return p.defaultClaimsMapping(claims)
}

// defaultClaimsMapping maps JWT claims to a Principal using default logic.
func (p *BearerProvider) defaultClaimsMapping(claims jwt.MapClaims) (*goauth.Principal, error) {
	// Extract user ID (try common claim names)
	var userID string
	for _, key := range []string{"sub", "user_id", "uid", "id"} {
		if v, ok := claims[key]; ok {
			userID = fmt.Sprintf("%v", v)
			break
		}
	}

	if userID == "" {
		return nil, goauth.NewAuthError(goauth.ErrCodeAuthInvalid, "missing user identifier in token", http.StatusUnauthorized)
	}

	principal := goauth.NewPrincipal(userID)

	// Extract roles (try common claim names)
	for _, key := range []string{"roles", "role", "groups", "authorities"} {
		if v, ok := claims[key]; ok {
			roles := extractStringSlice(v)
			principal.WithRoles(roles...)
			break
		}
	}

	// Extract permissions/scopes
	for _, key := range []string{"permissions", "scope", "scopes", "perms"} {
		if v, ok := claims[key]; ok {
			perms := extractStringSlice(v)
			principal.WithPermissions(perms...)
			break
		}
	}

	// Store all claims as metadata
	for k, v := range claims {
		// Skip standard claims we've already processed
		if k == "sub" || k == "roles" || k == "permissions" || k == "exp" || k == "iat" || k == "nbf" {
			continue
		}
		principal.WithMetadata(k, v)
	}

	return principal, nil
}

// defaultKeyFunc is the default key function for JWT validation.
func (p *BearerProvider) defaultKeyFunc(token *jwt.Token) (interface{}, error) {
	// Check the signing method
	switch token.Method.Alg() {
	case "HS256", "HS384", "HS512":
		if len(p.secretKey) == 0 {
			return nil, fmt.Errorf("secret key not configured for %s", token.Method.Alg())
		}
		return p.secretKey, nil
	case "RS256", "RS384", "RS512":
		if p.publicKey == nil {
			return nil, fmt.Errorf("public key not configured for %s", token.Method.Alg())
		}
		return p.publicKey, nil
	default:
		return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
	}
}

// extractStringSlice extracts a string slice from an interface value.
func extractStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case string:
		// Could be space-separated (OAuth2 scope format)
		return strings.Fields(val)
	default:
		return nil
	}
}

// containsAny checks if slice a contains any element from slice b.
func containsAny(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
