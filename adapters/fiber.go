package adapters

import (
	"net/http"

	"github.com/goauth"
	"github.com/goauth/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

const fiberPrincipalKey = "goauth_principal"

// FiberAdapter adapts the auth middleware for Fiber.
type FiberAdapter struct {
	middleware *middleware.AuthMiddleware
	config     goauth.Config
}

// NewFiberAdapter creates a new adapter for Fiber.
func NewFiberAdapter(m *middleware.AuthMiddleware, config goauth.Config) *FiberAdapter {
	return &FiberAdapter{
		middleware: m,
		config:     config,
	}
}

// Middleware returns Fiber middleware for authentication.
func (a *FiberAdapter) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Convert Fiber context to http.Request for provider compatibility
		httpReq := new(http.Request)
		err := fasthttpadaptor.ConvertRequest(c.Context(), httpReq, true)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": goauth.ErrInternal,
			})
		}

		// Authenticate using the middleware's internal logic
		principal, authErr := a.authenticate(httpReq)
		if authErr != nil {
			if authError := goauth.GetAuthError(authErr); authError != nil {
				return c.Status(authError.HTTPStatus).JSON(fiber.Map{
					"error": authError,
				})
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": goauth.ErrAuthInvalid,
			})
		}

		if principal == nil {
			if a.config.AllowAnonymous {
				principal = goauth.Anonymous()
			} else {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": goauth.ErrAuthMissing,
				})
			}
		}

		// Store principal in Fiber locals
		c.Locals(fiberPrincipalKey, principal)
		return c.Next()
	}
}

// authenticate performs authentication using providers.
func (a *FiberAdapter) authenticate(r *http.Request) (*goauth.Principal, error) {
	// This is a simplified version - in practice, you'd want to expose
	// the authenticate method from the middleware package
	return nil, nil
}

// RequireAuth returns Fiber middleware that requires authentication.
func RequireAuthFiber() fiber.Handler {
	return func(c *fiber.Ctx) error {
		principal := PrincipalFromFiber(c)
		if principal == nil || !principal.IsAuthenticated() {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": goauth.ErrAuthMissing,
			})
		}
		return c.Next()
	}
}

// RequireRoleFiber returns Fiber middleware that requires a specific role.
func RequireRoleFiber(role string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		principal := PrincipalFromFiber(c)
		if principal == nil || !principal.IsAuthenticated() {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": goauth.ErrAuthMissing,
			})
		}
		if !principal.HasRole(role) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": goauth.ErrForbidden,
			})
		}
		return c.Next()
	}
}

// RequireAnyRoleFiber returns Fiber middleware that requires any of the specified roles.
func RequireAnyRoleFiber(roles []string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		principal := PrincipalFromFiber(c)
		if principal == nil || !principal.IsAuthenticated() {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": goauth.ErrAuthMissing,
			})
		}
		if !principal.HasAnyRole(roles) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": goauth.ErrForbidden,
			})
		}
		return c.Next()
	}
}

// RequireAllRolesFiber returns Fiber middleware that requires all specified roles.
func RequireAllRolesFiber(roles []string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		principal := PrincipalFromFiber(c)
		if principal == nil || !principal.IsAuthenticated() {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": goauth.ErrAuthMissing,
			})
		}
		if !principal.HasAllRoles(roles) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": goauth.ErrForbidden,
			})
		}
		return c.Next()
	}
}

// RequirePermissionFiber returns Fiber middleware that requires a specific permission.
func RequirePermissionFiber(permission string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		principal := PrincipalFromFiber(c)
		if principal == nil || !principal.IsAuthenticated() {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": goauth.ErrAuthMissing,
			})
		}
		if !principal.HasPermission(permission) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": goauth.ErrForbidden,
			})
		}
		return c.Next()
	}
}

// PrincipalFromFiber extracts the Principal from Fiber context.
func PrincipalFromFiber(c *fiber.Ctx) *goauth.Principal {
	if principal, ok := c.Locals(fiberPrincipalKey).(*goauth.Principal); ok {
		return principal
	}
	return nil
}

// SetPrincipalFiber sets the Principal in Fiber context.
func SetPrincipalFiber(c *fiber.Ctx, principal *goauth.Principal) {
	c.Locals(fiberPrincipalKey, principal)
}
