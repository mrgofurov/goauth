// Package security provides security utilities for the auth framework.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// ConstantTimeCompare performs a constant-time comparison of two strings.
// This helps prevent timing attacks when comparing secrets.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ConstantTimeCompareBytes performs a constant-time comparison of two byte slices.
func ConstantTimeCompareBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GenerateSecureToken generates a cryptographically secure random token.
// The length parameter specifies the number of random bytes (the resulting
// base64 string will be longer).
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateSecureTokenHex generates a cryptographically secure random token as hex.
func GenerateSecureTokenHex(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// HashPassword hashes a password using bcrypt with the default cost.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// HashPasswordWithCost hashes a password using bcrypt with a custom cost.
func HashPasswordWithCost(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword compares a password against a bcrypt hash.
// Returns true if they match.
func VerifyPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateRandomBytes generates cryptographically secure random bytes.
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// SanitizeForLog removes sensitive characters from a string for safe logging.
// This masks all but the first and last few characters.
func SanitizeForLog(s string, visibleChars int) string {
	if len(s) <= visibleChars*2 {
		return "***"
	}
	return s[:visibleChars] + "***" + s[len(s)-visibleChars:]
}

// MaskToken masks a token for logging, showing only the first few characters.
func MaskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:4] + "..." + token[len(token)-4:]
}
