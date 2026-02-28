package goauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorCode represents a standard authentication/authorization error code.
type ErrorCode string

// Standard error codes
const (
	ErrCodeAuthMissing    ErrorCode = "AUTH_MISSING"
	ErrCodeAuthInvalid    ErrorCode = "AUTH_INVALID"
	ErrCodeAuthExpired    ErrorCode = "AUTH_EXPIRED"
	ErrCodeForbidden      ErrorCode = "FORBIDDEN"
	ErrCodeSessionInvalid ErrorCode = "SESSION_INVALID"
	ErrCodeBasicInvalid   ErrorCode = "BASIC_INVALID"
	ErrCodeInternal       ErrorCode = "INTERNAL_ERROR"
)

// AuthError represents an authentication or authorization error with standard fields.
type AuthError struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	HTTPStatus int       `json:"-"`
	Details    any       `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *AuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// WithDetails adds additional details to the error and returns it for chaining.
func (e *AuthError) WithDetails(details any) *AuthError {
	e.Details = details
	return e
}

// JSON returns the JSON representation of the error.
func (e *AuthError) JSON() []byte {
	data, _ := json.Marshal(e)
	return data
}

// WriteJSON writes the error as JSON to the http.ResponseWriter.
func (e *AuthError) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.HTTPStatus)
	w.Write(e.JSON())
}

// Pre-defined errors for common scenarios
var (
	// ErrAuthMissing indicates no authentication credentials were provided.
	ErrAuthMissing = &AuthError{
		Code:       ErrCodeAuthMissing,
		Message:    "Authentication credentials are missing",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrAuthInvalid indicates the provided credentials are invalid.
	ErrAuthInvalid = &AuthError{
		Code:       ErrCodeAuthInvalid,
		Message:    "Authentication credentials are invalid",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrAuthExpired indicates the token or session has expired.
	ErrAuthExpired = &AuthError{
		Code:       ErrCodeAuthExpired,
		Message:    "Authentication has expired",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrForbidden indicates the user lacks required permissions.
	ErrForbidden = &AuthError{
		Code:       ErrCodeForbidden,
		Message:    "Access forbidden: insufficient permissions",
		HTTPStatus: http.StatusForbidden,
	}

	// ErrSessionInvalid indicates the session is invalid or not found.
	ErrSessionInvalid = &AuthError{
		Code:       ErrCodeSessionInvalid,
		Message:    "Session is invalid or has expired",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrBasicInvalid indicates invalid basic auth credentials.
	ErrBasicInvalid = &AuthError{
		Code:       ErrCodeBasicInvalid,
		Message:    "Invalid username or password",
		HTTPStatus: http.StatusUnauthorized,
	}

	// ErrInternal indicates an internal server error during authentication.
	ErrInternal = &AuthError{
		Code:       ErrCodeInternal,
		Message:    "Internal authentication error",
		HTTPStatus: http.StatusInternalServerError,
	}
)

// NewAuthError creates a new AuthError with the given code, message, and HTTP status.
func NewAuthError(code ErrorCode, message string, httpStatus int) *AuthError {
	return &AuthError{
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
	}
}

// IsAuthError checks if an error is an AuthError.
func IsAuthError(err error) bool {
	_, ok := err.(*AuthError)
	return ok
}

// GetAuthError returns the AuthError if the error is one, otherwise nil.
func GetAuthError(err error) *AuthError {
	if authErr, ok := err.(*AuthError); ok {
		return authErr
	}
	return nil
}

// WrapError wraps a standard error into an AuthError with the given code.
func WrapError(code ErrorCode, err error, httpStatus int) *AuthError {
	return &AuthError{
		Code:       code,
		Message:    err.Error(),
		HTTPStatus: httpStatus,
	}
}

// ErrorResponse is the standard JSON error response format.
type ErrorResponse struct {
	Error *AuthError `json:"error"`
}

// NewErrorResponse creates an ErrorResponse from an AuthError.
func NewErrorResponse(err *AuthError) *ErrorResponse {
	return &ErrorResponse{Error: err}
}

// JSON returns the JSON representation of the error response.
func (r *ErrorResponse) JSON() []byte {
	data, _ := json.Marshal(r)
	return data
}
