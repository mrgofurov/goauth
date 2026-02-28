package middleware

import (
	"net/http"

	"github.com/goauth"
)

// Guard is a function that checks if a request is authorized.
type Guard func(principal *goauth.Principal) bool

// RequireAuth returns middleware that requires authentication.
func RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := PrincipalFromRequest(r)
			if principal == nil || !principal.IsAuthenticated() {
				goauth.ErrAuthMissing.WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns middleware that requires a specific role.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := PrincipalFromRequest(r)
			if principal == nil || !principal.IsAuthenticated() {
				goauth.ErrAuthMissing.WriteJSON(w)
				return
			}

			if !principal.HasRole(role) {
				goauth.ErrForbidden.WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole returns middleware that requires any of the specified roles.
func RequireAnyRole(roles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := PrincipalFromRequest(r)
			if principal == nil || !principal.IsAuthenticated() {
				goauth.ErrAuthMissing.WriteJSON(w)
				return
			}

			if !principal.HasAnyRole(roles) {
				goauth.ErrForbidden.WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllRoles returns middleware that requires all of the specified roles.
func RequireAllRoles(roles []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := PrincipalFromRequest(r)
			if principal == nil || !principal.IsAuthenticated() {
				goauth.ErrAuthMissing.WriteJSON(w)
				return
			}

			if !principal.HasAllRoles(roles) {
				goauth.ErrForbidden.WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission returns middleware that requires a specific permission.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := PrincipalFromRequest(r)
			if principal == nil || !principal.IsAuthenticated() {
				goauth.ErrAuthMissing.WriteJSON(w)
				return
			}

			if !principal.HasPermission(permission) {
				goauth.ErrForbidden.WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireGuard returns middleware that uses a custom guard function.
func RequireGuard(guard Guard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := PrincipalFromRequest(r)
			if principal == nil {
				goauth.ErrAuthMissing.WriteJSON(w)
				return
			}

			if !guard(principal) {
				goauth.ErrForbidden.WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Chain chains multiple middleware functions together.
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// And combines multiple guards with AND logic.
func And(guards ...Guard) Guard {
	return func(principal *goauth.Principal) bool {
		for _, guard := range guards {
			if !guard(principal) {
				return false
			}
		}
		return true
	}
}

// Or combines multiple guards with OR logic.
func Or(guards ...Guard) Guard {
	return func(principal *goauth.Principal) bool {
		for _, guard := range guards {
			if guard(principal) {
				return true
			}
		}
		return false
	}
}

// Not negates a guard.
func Not(guard Guard) Guard {
	return func(principal *goauth.Principal) bool {
		return !guard(principal)
	}
}

// HasRole returns a guard that checks for a specific role.
func HasRole(role string) Guard {
	return func(principal *goauth.Principal) bool {
		return principal != nil && principal.HasRole(role)
	}
}

// HasAnyRole returns a guard that checks for any of the specified roles.
func HasAnyRole(roles ...string) Guard {
	return func(principal *goauth.Principal) bool {
		return principal != nil && principal.HasAnyRole(roles)
	}
}

// HasAllRoles returns a guard that checks for all of the specified roles.
func HasAllRoles(roles ...string) Guard {
	return func(principal *goauth.Principal) bool {
		return principal != nil && principal.HasAllRoles(roles)
	}
}

// HasPermission returns a guard that checks for a specific permission.
func HasPermission(permission string) Guard {
	return func(principal *goauth.Principal) bool {
		return principal != nil && principal.HasPermission(permission)
	}
}

// IsAuthenticated returns a guard that checks if the principal is authenticated.
func IsAuthenticated() Guard {
	return func(principal *goauth.Principal) bool {
		return principal != nil && principal.IsAuthenticated()
	}
}
