// Package adapters provides framework-specific adapters for the auth middleware.
package adapters

import (
	"context"
	"net/http"

	"github.com/goauth"
	"github.com/goauth/middleware"
)

// NetHTTPAdapter adapts the auth middleware for net/http.
type NetHTTPAdapter struct {
	middleware *middleware.AuthMiddleware
}

// NewNetHTTPAdapter creates a new adapter for net/http.
func NewNetHTTPAdapter(m *middleware.AuthMiddleware) *NetHTTPAdapter {
	return &NetHTTPAdapter{middleware: m}
}

// Middleware returns the http.Handler middleware.
func (a *NetHTTPAdapter) Middleware() func(http.Handler) http.Handler {
	return a.middleware.Handler
}

// RequireAuth returns middleware that requires authentication.
func (a *NetHTTPAdapter) RequireAuth() func(http.Handler) http.Handler {
	return middleware.RequireAuth()
}

// RequireRole returns middleware that requires a specific role.
func (a *NetHTTPAdapter) RequireRole(role string) func(http.Handler) http.Handler {
	return middleware.RequireRole(role)
}

// RequireAnyRole returns middleware that requires any of the specified roles.
func (a *NetHTTPAdapter) RequireAnyRole(roles []string) func(http.Handler) http.Handler {
	return middleware.RequireAnyRole(roles)
}

// RequireAllRoles returns middleware that requires all of the specified roles.
func (a *NetHTTPAdapter) RequireAllRoles(roles []string) func(http.Handler) http.Handler {
	return middleware.RequireAllRoles(roles)
}

// RequirePermission returns middleware that requires a specific permission.
func (a *NetHTTPAdapter) RequirePermission(permission string) func(http.Handler) http.Handler {
	return middleware.RequirePermission(permission)
}

// PrincipalFromContext extracts the Principal from the context.
func PrincipalFromContext(ctx context.Context) *goauth.Principal {
	return middleware.PrincipalFromContext(ctx)
}

// PrincipalFromRequest extracts the Principal from the request.
func PrincipalFromRequest(r *http.Request) *goauth.Principal {
	return middleware.PrincipalFromRequest(r)
}

// WrapHandler wraps an http.HandlerFunc with middleware.
func WrapHandler(handler http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) http.Handler {
	var h http.Handler = handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
