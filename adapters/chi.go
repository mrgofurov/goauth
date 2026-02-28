package adapters

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/goauth"
	"github.com/goauth/middleware"
)

// ChiAdapter adapts the auth middleware for Chi.
type ChiAdapter struct {
	middleware *middleware.AuthMiddleware
}

// NewChiAdapter creates a new adapter for Chi.
func NewChiAdapter(m *middleware.AuthMiddleware) *ChiAdapter {
	return &ChiAdapter{middleware: m}
}

// Middleware returns Chi-compatible middleware for authentication.
// Chi uses standard http.Handler middleware, so this is the same as net/http.
func (a *ChiAdapter) Middleware() func(http.Handler) http.Handler {
	return a.middleware.Handler
}

// RequireAuth returns Chi middleware that requires authentication.
func (a *ChiAdapter) RequireAuth() func(http.Handler) http.Handler {
	return middleware.RequireAuth()
}

// RequireRole returns Chi middleware that requires a specific role.
func (a *ChiAdapter) RequireRole(role string) func(http.Handler) http.Handler {
	return middleware.RequireRole(role)
}

// RequireAnyRole returns Chi middleware that requires any of the specified roles.
func (a *ChiAdapter) RequireAnyRole(roles []string) func(http.Handler) http.Handler {
	return middleware.RequireAnyRole(roles)
}

// RequireAllRoles returns Chi middleware that requires all specified roles.
func (a *ChiAdapter) RequireAllRoles(roles []string) func(http.Handler) http.Handler {
	return middleware.RequireAllRoles(roles)
}

// RequirePermission returns Chi middleware that requires a specific permission.
func (a *ChiAdapter) RequirePermission(permission string) func(http.Handler) http.Handler {
	return middleware.RequirePermission(permission)
}

// PrincipalFromChi extracts the Principal from the Chi request context.
// This is the same as PrincipalFromContext since Chi uses standard context.
func PrincipalFromChi(r *http.Request) *goauth.Principal {
	return middleware.PrincipalFromRequest(r)
}

// ChiGroup creates a route group with the specified middleware.
func ChiGroup(r chi.Router, pattern string, middlewares ...func(http.Handler) http.Handler) chi.Router {
	return r.Route(pattern, func(sub chi.Router) {
		for _, m := range middlewares {
			sub.Use(m)
		}
	})
}
