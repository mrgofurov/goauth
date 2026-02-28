// Example: net/http with JWT authentication
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/goauth"
	"github.com/goauth/middleware"
	"github.com/goauth/providers"
	"github.com/goauth/security"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("your-super-secret-key-change-in-production")

func main() {
	// Create Bearer (JWT) provider
	bearer := providers.NewBearerProvider(
		providers.WithSecretKey(jwtSecret),
		providers.WithJWTConfig(goauth.JWTConfig{
			SigningMethod: "HS256",
			Leeway:        time.Minute,
		}),
	)

	// Create Basic auth provider with credential verifier
	basic := providers.NewBasicProvider(
		providers.WithCredentialVerifier(verifyCredentials),
		providers.WithRealm("Example API"),
	)

	// Create auth middleware with both providers
	authMiddleware := middleware.NewAuthMiddleware(
		middleware.WithProviders(bearer, basic),
		middleware.WithConfig(goauth.Config{
			ProviderPriority: []string{"bearer", "basic"},
			AllowAnonymous:   false,
		}),
		middleware.WithOnSuccess(func(event goauth.AuthEvent) {
			log.Printf("Auth success: user=%s provider=%s ip=%s", event.UserID, event.Provider, event.IP)
		}),
		middleware.WithOnFailure(func(event goauth.AuthEvent) {
			log.Printf("Auth failure: ip=%s error=%v", event.IP, event.Error)
		}),
	)

	// Create router
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/login", loginHandler)

	// Protected endpoints (require authentication)
	mux.Handle("/api/profile", authMiddleware.Handler(
		middleware.RequireAuth()(http.HandlerFunc(profileHandler)),
	))

	// Admin-only endpoint
	mux.Handle("/api/admin", authMiddleware.Handler(
		middleware.RequireRole("admin")(http.HandlerFunc(adminHandler)),
	))

	// Manager or Admin endpoint
	mux.Handle("/api/reports", authMiddleware.Handler(
		middleware.RequireAnyRole([]string{"admin", "manager"})(http.HandlerFunc(reportsHandler)),
	))

	log.Println("Server starting on :8080")
	log.Println("Try:")
	log.Println("  curl http://localhost:8080/health")
	log.Println("  curl -X POST http://localhost:8080/login -d '{\"username\":\"admin\",\"password\":\"admin123\"}'")
	log.Println("  curl -H 'Authorization: Bearer <token>' http://localhost:8080/api/profile")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Verify credentials (in production, check against database)
	principal, err := verifyCredentials(req.Username, req.Password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   principal.ID,
		"roles": principal.Roles,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
		"type":  "Bearer",
	})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	principal := middleware.PrincipalFromRequest(r)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":            principal.ID,
		"roles":         principal.Roles,
		"authenticated": principal.Authenticated,
	})
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	principal := middleware.PrincipalFromRequest(r)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"message": fmt.Sprintf("Welcome to admin area, %s!", principal.ID),
		"roles":   principal.Roles,
	})
}

func reportsHandler(w http.ResponseWriter, r *http.Request) {
	principal := middleware.PrincipalFromRequest(r)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"message": "Reports data",
		"user":    principal.ID,
	})
}

// Demo credential verifier (in production, use database + bcrypt)
func verifyCredentials(username, password string) (*goauth.Principal, error) {
	// Demo users (in production, store hashed passwords in database)
	users := map[string]struct {
		password string
		roles    []string
	}{
		"admin":   {"admin123", []string{"admin", "user"}},
		"manager": {"manager123", []string{"manager", "user"}},
		"user":    {"user123", []string{"user"}},
	}

	user, exists := users[username]
	if !exists {
		return nil, goauth.ErrBasicInvalid
	}

	// In production, use security.VerifyPassword(hashedPassword, password)
	if !security.ConstantTimeCompare(user.password, password) {
		return nil, goauth.ErrBasicInvalid
	}

	return goauth.NewPrincipal(username).WithRoles(user.roles...), nil
}
