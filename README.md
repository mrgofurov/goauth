# goauth

A reusable authentication and authorization framework for Go.

## Features

- **Multiple Auth Methods**: Bearer (JWT/Token), Basic Auth, Session
- **Framework Adapters**: net/http, Fiber, Gin, Chi
- **Role-Based Access Control**: RequireRole, RequireAnyRole, RequireAllRoles
- **Permission-Based Access**: RequirePermission
- **Pluggable Architecture**: Custom verifiers, session stores, token validators
- **Security Built-in**: Constant-time comparisons, bcrypt, session rotation

## Installation

```bash
go get github.com/mrgofurov/goauth
```

## Quick Start

### net/http Example

```go
package main

import (
    "net/http"
    
    "github.com/mrgofurov/goauth"
    "github.com/mrgofurov/goauth/middleware"
    "github.com/mrgofurov/goauth/providers"
)

func main() {
    // Create JWT provider
    bearer := providers.NewBearerProvider(
        providers.WithSecretKey([]byte("your-secret-key")),
    )

    // Create auth middleware
    authMiddleware := middleware.NewAuthMiddleware(
        middleware.WithProviders(bearer),
        middleware.WithConfig(goauth.DefaultConfig()),
    )

    // Create router
    mux := http.NewServeMux()
    
    // Public endpoint
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    })

    // Protected endpoint
    protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        principal := middleware.PrincipalFromRequest(r)
        w.Write([]byte("Hello, " + principal.ID))
    })
    
    mux.Handle("/protected", authMiddleware.Handler(
        middleware.RequireAuth()(protectedHandler),
    ))

    // Admin-only endpoint
    adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Admin area"))
    })
    
    mux.Handle("/admin", authMiddleware.Handler(
        middleware.RequireRole("admin")(adminHandler),
    ))

    http.ListenAndServe(":8080", mux)
}
```

### Fiber Example

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/mrgofurov/goauth"
    "github.com/mrgofurov/goauth/adapters"
    "github.com/mrgofurov/goauth/middleware"
    "github.com/mrgofurov/goauth/providers"
)

func main() {
    app := fiber.New()

    // Setup auth
    bearer := providers.NewBearerProvider(
        providers.WithSecretKey([]byte("your-secret-key")),
    )
    
    authMiddleware := middleware.NewAuthMiddleware(
        middleware.WithProviders(bearer),
    )
    
    fiberAdapter := adapters.NewFiberAdapter(authMiddleware, goauth.DefaultConfig())

    // Apply auth middleware
    app.Use(fiberAdapter.Middleware())

    // Protected route
    app.Get("/profile", adapters.RequireAuthFiber(), func(c *fiber.Ctx) error {
        principal := adapters.PrincipalFromFiber(c)
        return c.JSON(fiber.Map{"user": principal.ID})
    })

    app.Listen(":3000")
}
```

### Gin Example

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/mrgofurov/goauth"
    "github.com/mrgofurov/goauth/adapters"
    "github.com/mrgofurov/goauth/middleware"
    "github.com/mrgofurov/goauth/providers"
)

func main() {
    r := gin.Default()

    // Setup auth
    bearer := providers.NewBearerProvider(
        providers.WithSecretKey([]byte("your-secret-key")),
    )
    
    authMiddleware := middleware.NewAuthMiddleware(
        middleware.WithProviders(bearer),
    )
    
    ginAdapter := adapters.NewGinAdapter(authMiddleware, goauth.DefaultConfig())

    // Apply auth middleware
    r.Use(ginAdapter.Middleware())

    // Protected route
    r.GET("/profile", adapters.RequireAuthGin(), func(c *gin.Context) {
        principal := adapters.PrincipalFromGin(c)
        c.JSON(200, gin.H{"user": principal.ID})
    })

    r.Run(":8080")
}
```

## Configuration

```go
config := goauth.Config{
    // Enable specific providers (empty = all)
    EnabledProviders: []string{"bearer", "session"},
    
    // Provider priority order
    ProviderPriority: []string{"bearer", "session", "basic"},
    
    // Allow unauthenticated requests
    AllowAnonymous: false,
    
    // JWT settings
    JWT: goauth.JWTConfig{
        SigningMethod: "HS256",
        SecretKey:     []byte("your-secret"),
        Issuer:        "your-app",
        Audience:      []string{"your-api"},
        Leeway:        time.Minute,
    },
    
    // Session settings
    Session: goauth.SessionConfig{
        CookieName: "session_id",
        TTL:        24 * time.Hour,
        Secure:     true,
        HTTPOnly:   true,
        SameSite:   "Lax",
    },
    
    // Basic auth settings
    Basic: goauth.BasicConfig{
        Realm:           "Restricted",
        MaxAttempts:     5,
        LockoutDuration: 15 * time.Minute,
    },
}
```

## Auth Providers

### Bearer (JWT)

```go
bearer := providers.NewBearerProvider(
    providers.WithSecretKey([]byte("hmac-secret")),
    // OR for RSA
    providers.WithPublicKeyPEM(rsaPublicKeyPEM),
)
```

### Basic Auth

```go
basic := providers.NewBasicProvider(
    providers.WithCredentialVerifier(func(user, pass string) (*goauth.Principal, error) {
        // Verify against your database
        if user == "admin" && security.VerifyPassword(hashedPass, pass) {
            return goauth.NewPrincipal(user).WithRoles("admin"), nil
        }
        return nil, goauth.ErrBasicInvalid
    }),
)
```

### Session

```go
session := providers.NewSessionProvider(
    providers.WithSessionStore(providers.NewMemorySessionStore()),
    providers.WithSessionTTL(24 * time.Hour),
)
```

## Authorization Guards

```go
// Require authentication
middleware.RequireAuth()

// Require specific role
middleware.RequireRole("admin")

// Require any of multiple roles
middleware.RequireAnyRole([]string{"admin", "manager"})

// Require all roles
middleware.RequireAllRoles([]string{"verified", "premium"})

// Require permission
middleware.RequirePermission("orders.read")
```

## Security Utilities

```go
import "github.com/goauth/security"

// Hash password
hash, _ := security.HashPassword("user-password")

// Verify password
if security.VerifyPassword(hash, "user-password") {
    // Password matches
}

// Generate secure token
token, _ := security.GenerateSecureToken(32)

// Constant-time comparison
if security.ConstantTimeCompare(tokenA, tokenB) {
    // Tokens match
}
```

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTH_MISSING` | 401 | No credentials provided |
| `AUTH_INVALID` | 401 | Invalid credentials |
| `AUTH_EXPIRED` | 401 | Token/session expired |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `SESSION_INVALID` | 401 | Invalid session |
| `BASIC_INVALID` | 401 | Invalid basic auth |

## License

MIT
