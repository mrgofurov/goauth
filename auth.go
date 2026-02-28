package goauth

import (
	"net/http"
)

// Auth is the main authentication and authorization handler.
type Auth struct {
	config    Config
	providers []Authenticator
}

// New creates a new Auth instance with the given configuration and providers.
func New(config Config, providers ...Authenticator) *Auth {
	if err := config.Validate(); err != nil {
		// In production, you might want to handle this differently
		panic("invalid auth configuration: " + err.Error())
	}

	// Sort providers by priority
	sortedProviders := sortProvidersByPriority(providers, config.ProviderPriority)

	return &Auth{
		config:    config,
		providers: sortedProviders,
	}
}

// NewWithDefaults creates a new Auth instance with default configuration.
func NewWithDefaults(providers ...Authenticator) *Auth {
	return New(DefaultConfig(), providers...)
}

// Config returns the current configuration.
func (a *Auth) Config() Config {
	return a.config
}

// Providers returns the registered providers.
func (a *Auth) Providers() []Authenticator {
	return a.providers
}

// Authenticate attempts to authenticate a request using the configured providers.
func (a *Auth) Authenticate(r *http.Request) (*Principal, error) {
	var lastError error

	for _, provider := range a.providers {
		// Check if this provider is enabled
		if !a.isProviderEnabled(provider.Name()) {
			continue
		}

		// Check if this provider supports the request
		if !provider.Supports(r) {
			continue
		}

		principal, err := provider.Authenticate(r)
		if err != nil {
			lastError = err
			// Continue to try other providers on soft errors
			if authErr := GetAuthError(err); authErr != nil {
				if authErr.Code == ErrCodeAuthExpired {
					return nil, err
				}
			}
			continue
		}

		if principal != nil {
			// Log success event
			if a.config.LoggingHook != nil {
				a.config.LoggingHook(AuthEvent{
					Type:     AuthEventSuccess,
					Provider: provider.Name(),
					UserID:   principal.ID,
					IP:       getClientIP(r),
				})
			}
			return principal, nil
		}
	}

	// If we have an error from a provider, return it
	if lastError != nil {
		if a.config.LoggingHook != nil {
			a.config.LoggingHook(AuthEvent{
				Type:  AuthEventFailure,
				IP:    getClientIP(r),
				Error: lastError,
			})
		}
		return nil, lastError
	}

	// No provider authenticated the request
	if !a.config.AllowAnonymous {
		return nil, ErrAuthMissing
	}

	return Anonymous(), nil
}

// isProviderEnabled checks if a provider is enabled.
func (a *Auth) isProviderEnabled(name string) bool {
	if len(a.config.EnabledProviders) == 0 {
		return true
	}
	for _, enabled := range a.config.EnabledProviders {
		if enabled == name {
			return true
		}
	}
	return false
}

// sortProvidersByPriority sorts providers according to priority configuration.
func sortProvidersByPriority(providers []Authenticator, priority []string) []Authenticator {
	if len(priority) == 0 || len(providers) <= 1 {
		return providers
	}

	priorityMap := make(map[string]int)
	for i, name := range priority {
		priorityMap[name] = i
	}

	result := make([]Authenticator, 0, len(providers))

	// First, add providers in priority order
	for _, name := range priority {
		for _, p := range providers {
			if p.Name() == name {
				result = append(result, p)
				break
			}
		}
	}

	// Add remaining providers not in priority list
	for _, p := range providers {
		if _, exists := priorityMap[p.Name()]; !exists {
			result = append(result, p)
		}
	}

	return result
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	return r.RemoteAddr
}
