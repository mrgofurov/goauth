package providers

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goauth"
	"github.com/google/uuid"
)

// Session represents a user session.
type Session struct {
	ID          string
	UserID      string
	Roles       []string
	Permissions []string
	Metadata    map[string]any
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// ToPrincipal converts the session to a Principal.
func (s *Session) ToPrincipal() *goauth.Principal {
	principal := goauth.NewPrincipal(s.UserID)
	principal.WithRoles(s.Roles...)
	principal.WithPermissions(s.Permissions...)
	for k, v := range s.Metadata {
		principal.WithMetadata(k, v)
	}
	return principal
}

// SessionStore is the interface for session storage backends.
type SessionStore interface {
	// Get retrieves a session by ID.
	Get(id string) (*Session, error)

	// Set stores a session.
	Set(session *Session) error

	// Delete removes a session.
	Delete(id string) error

	// Rotate generates a new session ID while preserving session data.
	// Returns the new session with the updated ID.
	Rotate(oldID string) (*Session, error)
}

// SessionProvider implements session-based authentication.
type SessionProvider struct {
	store      SessionStore
	cookieName string
	headerName string
	ttl        time.Duration
	config     goauth.SessionConfig
}

// SessionOption is a functional option for configuring SessionProvider.
type SessionOption func(*SessionProvider)

// WithSessionStore sets the session store.
func WithSessionStore(store SessionStore) SessionOption {
	return func(p *SessionProvider) {
		p.store = store
	}
}

// WithCookieName sets the cookie name for session ID.
func WithCookieName(name string) SessionOption {
	return func(p *SessionProvider) {
		p.cookieName = name
	}
}

// WithHeaderName sets the header name for session ID.
func WithHeaderName(name string) SessionOption {
	return func(p *SessionProvider) {
		p.headerName = name
	}
}

// WithSessionTTL sets the session time-to-live.
func WithSessionTTL(ttl time.Duration) SessionOption {
	return func(p *SessionProvider) {
		p.ttl = ttl
	}
}

// WithSessionConfig sets the full session configuration.
func WithSessionConfig(config goauth.SessionConfig) SessionOption {
	return func(p *SessionProvider) {
		p.config = config
		p.cookieName = config.CookieName
		p.headerName = config.HeaderName
		p.ttl = config.TTL
	}
}

// NewSessionProvider creates a new SessionProvider with the given options.
func NewSessionProvider(opts ...SessionOption) *SessionProvider {
	p := &SessionProvider{
		cookieName: "session_id",
		headerName: "X-Session-Id",
		ttl:        24 * time.Hour,
	}

	for _, opt := range opts {
		opt(p)
	}

	// Use memory store if none provided
	if p.store == nil {
		p.store = NewMemorySessionStore()
	}

	return p
}

// Name returns the provider name.
func (p *SessionProvider) Name() string {
	return "session"
}

// Supports checks if the request has a session ID.
func (p *SessionProvider) Supports(r *http.Request) bool {
	// Check header first
	if r.Header.Get(p.headerName) != "" {
		return true
	}

	// Check cookie
	cookie, err := r.Cookie(p.cookieName)
	return err == nil && cookie.Value != ""
}

// Authenticate validates the session and returns the Principal.
func (p *SessionProvider) Authenticate(r *http.Request) (*goauth.Principal, error) {
	sessionID := p.extractSessionID(r)
	if sessionID == "" {
		return nil, nil // No session present, skip this provider
	}

	session, err := p.store.Get(sessionID)
	if err != nil {
		return nil, goauth.ErrSessionInvalid
	}

	if session == nil {
		return nil, goauth.ErrSessionInvalid
	}

	if session.IsExpired() {
		// Clean up expired session
		p.store.Delete(sessionID)
		return nil, goauth.ErrAuthExpired
	}

	return session.ToPrincipal(), nil
}

// extractSessionID extracts the session ID from cookie or header.
func (p *SessionProvider) extractSessionID(r *http.Request) string {
	// Check header first (allows API clients to use sessions)
	if headerValue := r.Header.Get(p.headerName); headerValue != "" {
		return strings.TrimSpace(headerValue)
	}

	// Check cookie
	cookie, err := r.Cookie(p.cookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}

// CreateSession creates a new session for the given principal.
func (p *SessionProvider) CreateSession(principal *goauth.Principal) (*Session, error) {
	session := &Session{
		ID:          uuid.New().String(),
		UserID:      principal.ID,
		Roles:       principal.Roles,
		Permissions: principal.Permissions,
		Metadata:    principal.Metadata,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(p.ttl),
	}

	if err := p.store.Set(session); err != nil {
		return nil, err
	}

	return session, nil
}

// DestroySession removes a session by ID.
func (p *SessionProvider) DestroySession(sessionID string) error {
	return p.store.Delete(sessionID)
}

// RotateSession creates a new session ID while preserving session data.
// This helps prevent session fixation attacks.
func (p *SessionProvider) RotateSession(oldSessionID string) (*Session, error) {
	return p.store.Rotate(oldSessionID)
}

// SetSessionCookie sets the session cookie on the response.
func (p *SessionProvider) SetSessionCookie(w http.ResponseWriter, session *Session) {
	cookie := &http.Cookie{
		Name:     p.cookieName,
		Value:    session.ID,
		Path:     p.config.Path,
		Domain:   p.config.Domain,
		Expires:  session.ExpiresAt,
		HttpOnly: p.config.HTTPOnly,
		Secure:   p.config.Secure,
	}

	switch strings.ToLower(p.config.SameSite) {
	case "strict":
		cookie.SameSite = http.SameSiteStrictMode
	case "none":
		cookie.SameSite = http.SameSiteNoneMode
	default:
		cookie.SameSite = http.SameSiteLaxMode
	}

	http.SetCookie(w, cookie)
}

// ClearSessionCookie removes the session cookie.
func (p *SessionProvider) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     p.cookieName,
		Value:    "",
		Path:     p.config.Path,
		Domain:   p.config.Domain,
		MaxAge:   -1,
		HttpOnly: p.config.HTTPOnly,
		Secure:   p.config.Secure,
	}
	http.SetCookie(w, cookie)
}

// Store returns the underlying session store.
func (p *SessionProvider) Store() SessionStore {
	return p.store
}

// MemorySessionStore is an in-memory session store for development/testing.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*Session),
	}
}

// Get retrieves a session by ID.
func (s *MemorySessionStore) Get(id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[id]
	if !exists {
		return nil, nil
	}

	// Return a copy to prevent mutation
	sessionCopy := *session
	return &sessionCopy, nil
}

// Set stores a session.
func (s *MemorySessionStore) Set(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation
	sessionCopy := *session
	s.sessions[session.ID] = &sessionCopy
	return nil
}

// Delete removes a session.
func (s *MemorySessionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)
	return nil
}

// Rotate generates a new session ID while preserving session data.
func (s *MemorySessionStore) Rotate(oldID string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[oldID]
	if !exists {
		return nil, goauth.ErrSessionInvalid
	}

	// Create new session with new ID
	newSession := &Session{
		ID:          uuid.New().String(),
		UserID:      session.UserID,
		Roles:       session.Roles,
		Permissions: session.Permissions,
		Metadata:    session.Metadata,
		CreatedAt:   session.CreatedAt,
		ExpiresAt:   session.ExpiresAt,
	}

	// Delete old session and store new
	delete(s.sessions, oldID)
	s.sessions[newSession.ID] = newSession

	return newSession, nil
}

// Cleanup removes expired sessions. Should be called periodically.
func (s *MemorySessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if session.ExpiresAt.Before(now) {
			delete(s.sessions, id)
		}
	}
}

// Count returns the number of active sessions.
func (s *MemorySessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
