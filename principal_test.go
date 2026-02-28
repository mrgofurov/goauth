package goauth

import (
	"testing"
)

func TestNewPrincipal(t *testing.T) {
	p := NewPrincipal("user123")

	if p.ID != "user123" {
		t.Errorf("expected ID 'user123', got '%s'", p.ID)
	}
	if !p.Authenticated {
		t.Error("expected Authenticated to be true")
	}
	if len(p.Roles) != 0 {
		t.Errorf("expected empty roles, got %v", p.Roles)
	}
}

func TestAnonymous(t *testing.T) {
	p := Anonymous()

	if p.Authenticated {
		t.Error("expected Authenticated to be false")
	}
	if p.ID != "" {
		t.Errorf("expected empty ID, got '%s'", p.ID)
	}
}

func TestPrincipal_WithRoles(t *testing.T) {
	p := NewPrincipal("user").WithRoles("Admin", "USER", "  manager  ")

	expected := []string{"admin", "user", "manager"}
	if len(p.Roles) != len(expected) {
		t.Errorf("expected %d roles, got %d", len(expected), len(p.Roles))
	}

	for i, role := range expected {
		if p.Roles[i] != role {
			t.Errorf("expected role '%s' at index %d, got '%s'", role, i, p.Roles[i])
		}
	}
}

func TestPrincipal_HasRole(t *testing.T) {
	p := NewPrincipal("user").WithRoles("admin", "user")

	tests := []struct {
		role     string
		expected bool
	}{
		{"admin", true},
		{"ADMIN", true}, // case insensitive
		{"Admin", true}, // case insensitive
		{"user", true},
		{"manager", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			if got := p.HasRole(tt.role); got != tt.expected {
				t.Errorf("HasRole(%q) = %v, want %v", tt.role, got, tt.expected)
			}
		})
	}
}

func TestPrincipal_HasAnyRole(t *testing.T) {
	p := NewPrincipal("user").WithRoles("admin", "user")

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"has admin", []string{"admin"}, true},
		{"has one of many", []string{"manager", "admin"}, true},
		{"has none", []string{"manager", "guest"}, false},
		{"empty roles", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.HasAnyRole(tt.roles); got != tt.expected {
				t.Errorf("HasAnyRole(%v) = %v, want %v", tt.roles, got, tt.expected)
			}
		})
	}
}

func TestPrincipal_HasAllRoles(t *testing.T) {
	p := NewPrincipal("user").WithRoles("admin", "user", "verified")

	tests := []struct {
		name     string
		roles    []string
		expected bool
	}{
		{"has all", []string{"admin", "user"}, true},
		{"has all three", []string{"admin", "user", "verified"}, true},
		{"missing one", []string{"admin", "manager"}, false},
		{"empty roles", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.HasAllRoles(tt.roles); got != tt.expected {
				t.Errorf("HasAllRoles(%v) = %v, want %v", tt.roles, got, tt.expected)
			}
		})
	}
}

func TestPrincipal_HasPermission(t *testing.T) {
	p := NewPrincipal("user").WithPermissions("read:users", "write:orders")

	tests := []struct {
		perm     string
		expected bool
	}{
		{"read:users", true},
		{"READ:USERS", true}, // case insensitive
		{"write:orders", true},
		{"delete:users", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.perm, func(t *testing.T) {
			if got := p.HasPermission(tt.perm); got != tt.expected {
				t.Errorf("HasPermission(%q) = %v, want %v", tt.perm, got, tt.expected)
			}
		})
	}
}

func TestPrincipal_Metadata(t *testing.T) {
	p := NewPrincipal("user").
		WithMetadata("key1", "value1").
		WithMetadata("key2", 123)

	if p.GetMetadata("key1") != "value1" {
		t.Errorf("expected 'value1', got %v", p.GetMetadata("key1"))
	}
	if p.GetMetadata("key2") != 123 {
		t.Errorf("expected 123, got %v", p.GetMetadata("key2"))
	}
	if p.GetMetadata("nonexistent") != nil {
		t.Errorf("expected nil for nonexistent key")
	}
}

func TestNormalizeRoles(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{"normal", []string{"Admin", "User"}, []string{"admin", "user"}},
		{"with spaces", []string{"  admin  ", "user"}, []string{"admin", "user"}},
		{"duplicates", []string{"admin", "ADMIN", "Admin"}, []string{"admin"}},
		{"empty strings", []string{"admin", "", "  ", "user"}, []string{"admin", "user"}},
		{"empty slice", []string{}, []string{}},
		{"nil slice", nil, []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeRoles(tt.input)
			if len(got) != len(tt.expected) {
				t.Errorf("NormalizeRoles(%v) = %v, want %v", tt.input, got, tt.expected)
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("NormalizeRoles(%v)[%d] = %v, want %v", tt.input, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestPrincipal_NilSafety(t *testing.T) {
	var p *Principal

	if p.HasRole("admin") {
		t.Error("nil principal should not have any role")
	}
	if p.HasAnyRole([]string{"admin"}) {
		t.Error("nil principal should not have any role")
	}
	if p.HasAllRoles([]string{}) != true {
		t.Error("nil principal HasAllRoles with empty should return true")
	}
	if p.HasPermission("read") {
		t.Error("nil principal should not have any permission")
	}
	if p.IsAuthenticated() {
		t.Error("nil principal should not be authenticated")
	}
	if p.GetMetadata("key") != nil {
		t.Error("nil principal GetMetadata should return nil")
	}
}
