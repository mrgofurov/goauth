// Example: Gin with combined authentication
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goauth"
	"github.com/goauth/adapters"
	"github.com/goauth/providers"
	"github.com/goauth/security"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("gin-example-secret-key")

func main() {
	r := gin.Default()

	// Create providers
	bearer := providers.NewBearerProvider(
		providers.WithSecretKey(jwtSecret),
	)

	basic := providers.NewBasicProvider(
		providers.WithCredentialVerifier(verifyCredentials),
	)

	// Session store
	sessionStore := providers.NewMemorySessionStore()
	session := providers.NewSessionProvider(
		providers.WithSessionStore(sessionStore),
	)

	_ = session // Use session provider as needed

	// Public routes
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.POST("/login", loginHandler)

	// Protected routes with custom middleware
	api := r.Group("/api")
	api.Use(authMiddleware(bearer, basic))
	{
		api.GET("/profile", adapters.RequireAuthGin(), profileHandler)
		api.GET("/admin", adapters.RequireRoleGin("admin"), adminHandler)
		api.GET("/managers", adapters.RequireAnyRoleGin([]string{"admin", "manager"}), managersHandler)
	}

	log.Println("Gin server starting on :8080")
	log.Println("Try:")
	log.Println("  curl http://localhost:8080/health")
	log.Println("  curl -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"admin123\"}'")

	r.Run(":8080")
}

func authMiddleware(bearer *providers.BearerProvider, basic *providers.BasicProvider) gin.HandlerFunc {
	return func(c *gin.Context) {
		var principal *goauth.Principal
		var err error

		// Try bearer first
		if bearer.Supports(c.Request) {
			principal, err = bearer.Authenticate(c.Request)
			if err == nil && principal != nil {
				adapters.SetPrincipalGin(c, principal)
				c.Next()
				return
			}
		}

		// Try basic auth
		if basic.Supports(c.Request) {
			principal, err = basic.Authenticate(c.Request)
			if err == nil && principal != nil {
				adapters.SetPrincipalGin(c, principal)
				c.Next()
				return
			}
		}

		// Check if we had an error
		if err != nil {
			if authErr := goauth.GetAuthError(err); authErr != nil {
				c.AbortWithStatusJSON(authErr.HTTPStatus, gin.H{"error": authErr})
				return
			}
		}

		// No authentication provided
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": goauth.ErrAuthMissing,
		})
	}
}

func loginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	principal, err := verifyCredentials(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   principal.ID,
		"roles": principal.Roles,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"type":  "Bearer",
	})
}

func profileHandler(c *gin.Context) {
	principal := adapters.PrincipalFromGin(c)
	c.JSON(http.StatusOK, gin.H{
		"id":    principal.ID,
		"roles": principal.Roles,
	})
}

func adminHandler(c *gin.Context) {
	principal := adapters.PrincipalFromGin(c)
	c.JSON(http.StatusOK, gin.H{
		"message": "Admin area",
		"user":    principal.ID,
	})
}

func managersHandler(c *gin.Context) {
	principal := adapters.PrincipalFromGin(c)
	c.JSON(http.StatusOK, gin.H{
		"message": "Managers area",
		"user":    principal.ID,
		"roles":   principal.Roles,
	})
}

func verifyCredentials(username, password string) (*goauth.Principal, error) {
	users := map[string]struct {
		password string
		roles    []string
	}{
		"admin":   {"admin123", []string{"admin", "user"}},
		"manager": {"manager123", []string{"manager", "user"}},
		"user":    {"user123", []string{"user"}},
	}

	user, exists := users[username]
	if !exists || !security.ConstantTimeCompare(user.password, password) {
		return nil, goauth.ErrBasicInvalid
	}

	return goauth.NewPrincipal(username).WithRoles(user.roles...), nil
}
