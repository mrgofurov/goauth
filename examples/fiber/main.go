// Example: Fiber with session authentication
package main

import (
	"log"
	"time"

	"github.com/goauth"
	"github.com/goauth/adapters"
	"github.com/goauth/providers"
	"github.com/goauth/security"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New(fiber.Config{
		ErrorHandler: customErrorHandler,
	})

	// Create session provider with memory store
	sessionStore := providers.NewMemorySessionStore()
	sessionProvider := providers.NewSessionProvider(
		providers.WithSessionStore(sessionStore),
		providers.WithSessionTTL(24*time.Hour),
		providers.WithSessionConfig(goauth.SessionConfig{
			CookieName: "session_id",
			HTTPOnly:   true,
			Secure:     false, // Set to true in production with HTTPS
			SameSite:   "Lax",
			Path:       "/",
		}),
	)

	// Public routes
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Login endpoint - creates a session
	app.Post("/login", func(c *fiber.Ctx) error {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
		}

		// Demo authentication
		principal, err := authenticate(req.Username, req.Password)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"error": "Invalid credentials"})
		}

		// Create session
		session, err := sessionProvider.CreateSession(principal)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "Session creation failed"})
		}

		// Set cookie
		c.Cookie(&fiber.Cookie{
			Name:     "session_id",
			Value:    session.ID,
			Expires:  session.ExpiresAt,
			HTTPOnly: true,
			Secure:   false,
			SameSite: "Lax",
		})

		return c.JSON(fiber.Map{
			"message":    "Login successful",
			"session_id": session.ID,
			"expires":    session.ExpiresAt,
		})
	})

	// Logout endpoint
	app.Post("/logout", func(c *fiber.Ctx) error {
		sessionID := c.Cookies("session_id")
		if sessionID != "" {
			sessionProvider.DestroySession(sessionID)
		}

		c.Cookie(&fiber.Cookie{
			Name:     "session_id",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
		})

		return c.JSON(fiber.Map{"message": "Logged out"})
	})

	// Protected routes group
	api := app.Group("/api")

	// Custom auth middleware for Fiber
	api.Use(func(c *fiber.Ctx) error {
		// Try session first
		sessionID := c.Cookies("session_id")
		if sessionID == "" {
			sessionID = c.Get("X-Session-Id")
		}

		if sessionID != "" {
			session, err := sessionStore.Get(sessionID)
			if err == nil && session != nil && !session.IsExpired() {
				adapters.SetPrincipalFiber(c, session.ToPrincipal())
				return c.Next()
			}
		}

		// No valid session found
		return c.Status(401).JSON(fiber.Map{"error": goauth.ErrAuthMissing})
	})

	// Protected endpoints
	api.Get("/profile", adapters.RequireAuthFiber(), func(c *fiber.Ctx) error {
		principal := adapters.PrincipalFromFiber(c)
		return c.JSON(fiber.Map{
			"user":  principal.ID,
			"roles": principal.Roles,
		})
	})

	api.Get("/admin", adapters.RequireRoleFiber("admin"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Admin area"})
	})

	log.Println("Fiber server starting on :3000")
	log.Println("Try:")
	log.Println("  curl http://localhost:3000/health")
	log.Println("  curl -X POST http://localhost:3000/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"admin123\"}'")

	log.Fatal(app.Listen(":3000"))
}

func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	return c.Status(code).JSON(fiber.Map{"error": err.Error()})
}

func authenticate(username, password string) (*goauth.Principal, error) {
	users := map[string]struct {
		password string
		roles    []string
	}{
		"admin": {"admin123", []string{"admin", "user"}},
		"user":  {"user123", []string{"user"}},
	}

	user, exists := users[username]
	if !exists || !security.ConstantTimeCompare(user.password, password) {
		return nil, goauth.ErrBasicInvalid
	}

	return goauth.NewPrincipal(username).WithRoles(user.roles...), nil
}
