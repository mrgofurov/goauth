// Package goauth provides a reusable authentication and authorization framework for Go.
// It supports Bearer (JWT/Token), Basic, and Session authentication methods with
// adapters for net/http, Fiber, Gin, and Chi.
package goauth

import (
	"strings"
)

// Principal represents an authenticated user/entity.
// It contains identity information, roles, permissions, and custom metadata.
type Principal struct {
	// ID is the unique identifier for the user (string, UUID, or int64 as string)
	ID string

	// Roles contains the user's roles, always normalized to a slice
	Roles []string

	// Permissions contains optional scopes/permissions
	Permissions []string

	// Authenticated indicates whether the principal has been authenticated
	Authenticated bool

	// Metadata contains additional custom data
	Metadata map[string]any
}

// Anonymous returns a new anonymous (unauthenticated) principal.
func Anonymous() *Principal {
	return &Principal{
		Authenticated: false,
		Roles:         []string{},
		Permissions:   []string{},
		Metadata:      make(map[string]any),
	}
}

// NewPrincipal creates a new authenticated principal with the given ID.
func NewPrincipal(id string) *Principal {
	return &Principal{
		ID:            id,
		Authenticated: true,
		Roles:         []string{},
		Permissions:   []string{},
		Metadata:      make(map[string]any),
	}
}

// WithRoles sets the principal's roles and returns the principal for chaining.
// Roles are normalized: trimmed, lowercased, and deduplicated.
func (p *Principal) WithRoles(roles ...string) *Principal {
	p.Roles = normalizeRoles(roles)
	return p
}

// WithPermissions sets the principal's permissions and returns the principal for chaining.
func (p *Principal) WithPermissions(permissions ...string) *Principal {
	p.Permissions = normalizeRoles(permissions) // same normalization logic
	return p
}

// WithMetadata sets a metadata key-value pair and returns the principal for chaining.
func (p *Principal) WithMetadata(key string, value any) *Principal {
	if p.Metadata == nil {
		p.Metadata = make(map[string]any)
	}
	p.Metadata[key] = value
	return p
}

// HasRole checks if the principal has the specified role (case-insensitive).
func (p *Principal) HasRole(role string) bool {
	if p == nil || len(p.Roles) == 0 {
		return false
	}
	normalizedRole := strings.ToLower(strings.TrimSpace(role))
	for _, r := range p.Roles {
		if r == normalizedRole {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the principal has at least one of the specified roles.
func (p *Principal) HasAnyRole(roles []string) bool {
	if p == nil || len(p.Roles) == 0 || len(roles) == 0 {
		return false
	}
	for _, role := range roles {
		if p.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAllRoles checks if the principal has all of the specified roles.
func (p *Principal) HasAllRoles(roles []string) bool {
	if p == nil || len(p.Roles) == 0 {
		return len(roles) == 0
	}
	for _, role := range roles {
		if !p.HasRole(role) {
			return false
		}
	}
	return true
}

// HasPermission checks if the principal has the specified permission (case-insensitive).
func (p *Principal) HasPermission(permission string) bool {
	if p == nil || len(p.Permissions) == 0 {
		return false
	}
	normalizedPerm := strings.ToLower(strings.TrimSpace(permission))
	for _, perm := range p.Permissions {
		if perm == normalizedPerm {
			return true
		}
	}
	return false
}

// IsAuthenticated returns true if the principal is authenticated.
func (p *Principal) IsAuthenticated() bool {
	return p != nil && p.Authenticated
}

// GetMetadata retrieves a metadata value by key.
// Returns nil if the key doesn't exist.
func (p *Principal) GetMetadata(key string) any {
	if p == nil || p.Metadata == nil {
		return nil
	}
	return p.Metadata[key]
}

// normalizeRoles normalizes a slice of roles: trims whitespace, lowercases, and deduplicates.
func normalizeRoles(roles []string) []string {
	if len(roles) == 0 {
		return []string{}
	}

	seen := make(map[string]bool)
	result := make([]string, 0, len(roles))

	for _, role := range roles {
		normalized := strings.ToLower(strings.TrimSpace(role))
		if normalized == "" {
			continue
		}
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, normalized)
		}
	}

	return result
}

// NormalizeRole normalizes a single role string.
func NormalizeRole(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

// NormalizeRoles normalizes a slice of roles (exported version).
func NormalizeRoles(roles []string) []string {
	return normalizeRoles(roles)
}
