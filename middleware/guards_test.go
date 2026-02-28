package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goauth"
)

func createRequestWithPrincipal(principal *goauth.Principal) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := SetPrincipal(req.Context(), principal)
	return req.WithContext(ctx)
}

func TestRequireAuth(t *testing.T) {
	handler := RequireAuth()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	tests := []struct {
		name       string
		principal  *goauth.Principal
		wantStatus int
	}{
		{"authenticated", goauth.NewPrincipal("user"), 200},
		{"anonymous", goauth.Anonymous(), 401},
		{"nil", nil, 401},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createRequestWithPrincipal(tt.principal)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestRequireRole(t *testing.T) {
	handler := RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	tests := []struct {
		name       string
		principal  *goauth.Principal
		wantStatus int
	}{
		{"has role", goauth.NewPrincipal("user").WithRoles("admin"), 200},
		{"missing role", goauth.NewPrincipal("user").WithRoles("user"), 403},
		{"not authenticated", goauth.Anonymous(), 401},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createRequestWithPrincipal(tt.principal)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestRequireAnyRole(t *testing.T) {
	handler := RequireAnyRole([]string{"admin", "manager"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	tests := []struct {
		name       string
		roles      []string
		wantStatus int
	}{
		{"has admin", []string{"admin"}, 200},
		{"has manager", []string{"manager"}, 200},
		{"has both", []string{"admin", "manager"}, 200},
		{"has neither", []string{"user"}, 403},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := goauth.NewPrincipal("user").WithRoles(tt.roles...)
			req := createRequestWithPrincipal(principal)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestRequireAllRoles(t *testing.T) {
	handler := RequireAllRoles([]string{"admin", "verified"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	tests := []struct {
		name       string
		roles      []string
		wantStatus int
	}{
		{"has all", []string{"admin", "verified"}, 200},
		{"has more", []string{"admin", "verified", "user"}, 200},
		{"missing one", []string{"admin"}, 403},
		{"missing all", []string{"user"}, 403},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := goauth.NewPrincipal("user").WithRoles(tt.roles...)
			req := createRequestWithPrincipal(principal)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestRequirePermission(t *testing.T) {
	handler := RequirePermission("orders.read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	tests := []struct {
		name        string
		permissions []string
		wantStatus  int
	}{
		{"has permission", []string{"orders.read"}, 200},
		{"missing permission", []string{"orders.write"}, 403},
		{"no permissions", []string{}, 403},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := goauth.NewPrincipal("user").WithPermissions(tt.permissions...)
			req := createRequestWithPrincipal(principal)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}

func TestGuardCombinations(t *testing.T) {
	// Test And
	andGuard := And(HasRole("admin"), HasRole("verified"))
	principal := goauth.NewPrincipal("user").WithRoles("admin", "verified")
	if !andGuard(principal) {
		t.Error("And guard should pass")
	}

	principal2 := goauth.NewPrincipal("user").WithRoles("admin")
	if andGuard(principal2) {
		t.Error("And guard should fail when missing role")
	}

	// Test Or
	orGuard := Or(HasRole("admin"), HasRole("manager"))
	if !orGuard(goauth.NewPrincipal("u").WithRoles("admin")) {
		t.Error("Or guard should pass with admin")
	}
	if !orGuard(goauth.NewPrincipal("u").WithRoles("manager")) {
		t.Error("Or guard should pass with manager")
	}
	if orGuard(goauth.NewPrincipal("u").WithRoles("user")) {
		t.Error("Or guard should fail with neither role")
	}

	// Test Not
	notGuard := Not(HasRole("banned"))
	if !notGuard(goauth.NewPrincipal("u").WithRoles("user")) {
		t.Error("Not guard should pass when role is absent")
	}
	if notGuard(goauth.NewPrincipal("u").WithRoles("banned")) {
		t.Error("Not guard should fail when role is present")
	}
}

func TestChain(t *testing.T) {
	callOrder := []string{}

	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callOrder = append(callOrder, "m1")
			next.ServeHTTP(w, r)
		})
	}

	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callOrder = append(callOrder, "m2")
			next.ServeHTTP(w, r)
		})
	}

	handler := Chain(m1, m2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callOrder = append(callOrder, "handler")
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	expected := []string{"m1", "m2", "handler"}
	for i, v := range expected {
		if callOrder[i] != v {
			t.Errorf("expected %v, got %v", expected, callOrder)
			break
		}
	}
}
