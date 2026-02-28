// Package middleware provides authentication and authorization middleware.
package middleware

import (
	"context"
	"net/http"

	"github.com/goauth"
)

// principalContextKey is the context key for storing the Principal.
type principalContextKey struct{}

// AuthMiddleware is the main authentication middleware.
type AuthMiddleware struct {
	providers    []goauth.Authenticator
	config       goauth.Config
	onSuccess    func(goauth.AuthEvent)
	onFailure    func(goauth.AuthEvent)
	errorHandler ErrorHandler
}

// ErrorHandler is a function that handles authentication errors.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err *goauth.AuthError)

// MiddlewareOption is a functional option for configuring AuthMiddleware.
type MiddlewareOption func(*AuthMiddleware)

// WithProviders sets the authentication providers.
func WithProviders(providers ...goauth.Authenticator) MiddlewareOption {
	return func(m *AuthMiddleware) {
		m.providers = providers
	}
}

// WithConfig sets the middleware configuration.
func WithConfig(config goauth.Config) MiddlewareOption {
	return func(m *AuthMiddleware) {
		m.config = config
	}
}

// WithOnSuccess sets a callback for successful authentication.
func WithOnSuccess(fn func(goauth.AuthEvent)) MiddlewareOption {
	return func(m *AuthMiddleware) {
		m.onSuccess = fn
	}
}

// WithOnFailure sets a callback for failed authentication.
func WithOnFailure(fn func(goauth.AuthEvent)) MiddlewareOption {
	return func(m *AuthMiddleware) {
		m.onFailure = fn
	}
}

// WithErrorHandler sets a custom error handler.
func WithErrorHandler(handler ErrorHandler) MiddlewareOption {
	return func(m *AuthMiddleware) {
		m.errorHandler = handler
	}
}

// NewAuthMiddleware creates a new AuthMiddleware with the given options.
func NewAuthMiddleware(opts ...MiddlewareOption) *AuthMiddleware {
	m := &AuthMiddleware{
		config:       goauth.DefaultConfig(),
		errorHandler: defaultErrorHandler,
	}

	for _, opt := range opts {
		opt(m)
	}

	// Sort providers by priority if configured
	if len(m.config.ProviderPriority) > 0 && len(m.providers) > 1 {
		m.providers = sortByPriority(m.providers, m.config.ProviderPriority)
	}

	return m
}

// Handler returns an http.Handler middleware that authenticates requests.
func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := m.authenticate(r)

		if err != nil {
			// Emit failure event
			if m.onFailure != nil {
				m.onFailure(goauth.AuthEvent{
					Type:      goauth.AuthEventFailure,
					IP:        getClientIP(r),
					UserAgent: r.UserAgent(),
					Error:     err,
				})
			}

			authErr := goauth.GetAuthError(err)
			if authErr == nil {
				authErr = goauth.ErrAuthInvalid
			}
			m.errorHandler(w, r, authErr)
			return
		}

		if principal == nil {
			if m.config.AllowAnonymous {
				principal = goauth.Anonymous()
			} else {
				m.errorHandler(w, r, goauth.ErrAuthMissing)
				return
			}
		}

		// Emit success event
		if m.onSuccess != nil && principal.Authenticated {
			m.onSuccess(goauth.AuthEvent{
				Type:      goauth.AuthEventSuccess,
				UserID:    principal.ID,
				IP:        getClientIP(r),
				UserAgent: r.UserAgent(),
			})
		}

		// Store principal in context
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate tries each provider in order until one succeeds.
func (m *AuthMiddleware) authenticate(r *http.Request) (*goauth.Principal, error) {
	var lastError error

	for _, provider := range m.providers {
		// Check if this provider is enabled
		if !m.isProviderEnabled(provider.Name()) {
			continue
		}

		// Check if this provider supports the request
		if !provider.Supports(r) {
			continue
		}

		principal, err := provider.Authenticate(r)
		if err != nil {
			lastError = err
			// Continue to try other providers on soft errors
			if authErr := goauth.GetAuthError(err); authErr != nil {
				// Stop on hard errors like expired tokens
				if authErr.Code == goauth.ErrCodeAuthExpired {
					return nil, err
				}
			}
			continue
		}

		if principal != nil {
			return principal, nil
		}
	}

	// If we have an error from a provider that was tried, return it
	if lastError != nil {
		return nil, lastError
	}

	// No provider authenticated the request
	return nil, nil
}

// isProviderEnabled checks if a provider is enabled in the configuration.
func (m *AuthMiddleware) isProviderEnabled(name string) bool {
	if len(m.config.EnabledProviders) == 0 {
		return true // All providers enabled by default
	}

	for _, enabled := range m.config.EnabledProviders {
		if enabled == name {
			return true
		}
	}
	return false
}

// PrincipalFromContext extracts the Principal from the request context.
func PrincipalFromContext(ctx context.Context) *goauth.Principal {
	if principal, ok := ctx.Value(principalContextKey{}).(*goauth.Principal); ok {
		return principal
	}
	return nil
}

// PrincipalFromRequest extracts the Principal from the request.
func PrincipalFromRequest(r *http.Request) *goauth.Principal {
	return PrincipalFromContext(r.Context())
}

// SetPrincipal sets the Principal in the context and returns the new context.
func SetPrincipal(ctx context.Context, principal *goauth.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// defaultErrorHandler is the default error handler that returns JSON errors.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err *goauth.AuthError) {
	err.WriteJSON(w)
}

// sortByPriority sorts providers according to the priority order.
func sortByPriority(providers []goauth.Authenticator, priority []string) []goauth.Authenticator {
	priorityMap := make(map[string]int)
	for i, name := range priority {
		priorityMap[name] = i
	}

	// Create a new slice with providers sorted by priority
	result := make([]goauth.Authenticator, 0, len(providers))

	// First, add providers in priority order
	for _, name := range priority {
		for _, p := range providers {
			if p.Name() == name {
				result = append(result, p)
				break
			}
		}
	}

	// Add remaining providers not in priority list
	for _, p := range providers {
		if _, exists := priorityMap[p.Name()]; !exists {
			result = append(result, p)
		}
	}

	return result
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
