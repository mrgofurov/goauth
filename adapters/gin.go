package adapters

import (
	"github.com/gin-gonic/gin"
	"github.com/goauth"
	"github.com/goauth/middleware"
)

const ginPrincipalKey = "goauth_principal"

// GinAdapter adapts the auth middleware for Gin.
type GinAdapter struct {
	middleware *middleware.AuthMiddleware
	config     goauth.Config
}

// NewGinAdapter creates a new adapter for Gin.
func NewGinAdapter(m *middleware.AuthMiddleware, config goauth.Config) *GinAdapter {
	return &GinAdapter{
		middleware: m,
		config:     config,
	}
}

// Middleware returns Gin middleware for authentication.
func (a *GinAdapter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use the http.Request directly from Gin
		principal, err := a.authenticate(c)
		if err != nil {
			if authError := goauth.GetAuthError(err); authError != nil {
				c.AbortWithStatusJSON(authError.HTTPStatus, gin.H{
					"error": authError,
				})
				return
			}
			c.AbortWithStatusJSON(401, gin.H{
				"error": goauth.ErrAuthInvalid,
			})
			return
		}

		if principal == nil {
			if a.config.AllowAnonymous {
				principal = goauth.Anonymous()
			} else {
				c.AbortWithStatusJSON(401, gin.H{
					"error": goauth.ErrAuthMissing,
				})
				return
			}
		}

		// Store principal in Gin context
		c.Set(ginPrincipalKey, principal)
		c.Next()
	}
}

// authenticate performs authentication using providers.
func (a *GinAdapter) authenticate(c *gin.Context) (*goauth.Principal, error) {
	// This is a simplified version - would use the actual provider chain
	return nil, nil
}

// RequireAuthGin returns Gin middleware that requires authentication.
func RequireAuthGin() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal := PrincipalFromGin(c)
		if principal == nil || !principal.IsAuthenticated() {
			c.AbortWithStatusJSON(401, gin.H{
				"error": goauth.ErrAuthMissing,
			})
			return
		}
		c.Next()
	}
}

// RequireRoleGin returns Gin middleware that requires a specific role.
func RequireRoleGin(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal := PrincipalFromGin(c)
		if principal == nil || !principal.IsAuthenticated() {
			c.AbortWithStatusJSON(401, gin.H{
				"error": goauth.ErrAuthMissing,
			})
			return
		}
		if !principal.HasRole(role) {
			c.AbortWithStatusJSON(403, gin.H{
				"error": goauth.ErrForbidden,
			})
			return
		}
		c.Next()
	}
}

// RequireAnyRoleGin returns Gin middleware that requires any of the specified roles.
func RequireAnyRoleGin(roles []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal := PrincipalFromGin(c)
		if principal == nil || !principal.IsAuthenticated() {
			c.AbortWithStatusJSON(401, gin.H{
				"error": goauth.ErrAuthMissing,
			})
			return
		}
		if !principal.HasAnyRole(roles) {
			c.AbortWithStatusJSON(403, gin.H{
				"error": goauth.ErrForbidden,
			})
			return
		}
		c.Next()
	}
}

// RequireAllRolesGin returns Gin middleware that requires all specified roles.
func RequireAllRolesGin(roles []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal := PrincipalFromGin(c)
		if principal == nil || !principal.IsAuthenticated() {
			c.AbortWithStatusJSON(401, gin.H{
				"error": goauth.ErrAuthMissing,
			})
			return
		}
		if !principal.HasAllRoles(roles) {
			c.AbortWithStatusJSON(403, gin.H{
				"error": goauth.ErrForbidden,
			})
			return
		}
		c.Next()
	}
}

// RequirePermissionGin returns Gin middleware that requires a specific permission.
func RequirePermissionGin(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal := PrincipalFromGin(c)
		if principal == nil || !principal.IsAuthenticated() {
			c.AbortWithStatusJSON(401, gin.H{
				"error": goauth.ErrAuthMissing,
			})
			return
		}
		if !principal.HasPermission(permission) {
			c.AbortWithStatusJSON(403, gin.H{
				"error": goauth.ErrForbidden,
			})
			return
		}
		c.Next()
	}
}

// PrincipalFromGin extracts the Principal from Gin context.
func PrincipalFromGin(c *gin.Context) *goauth.Principal {
	if principal, exists := c.Get(ginPrincipalKey); exists {
		if p, ok := principal.(*goauth.Principal); ok {
			return p
		}
	}
	return nil
}

// SetPrincipalGin sets the Principal in Gin context.
func SetPrincipalGin(c *gin.Context, principal *goauth.Principal) {
	c.Set(ginPrincipalKey, principal)
}
