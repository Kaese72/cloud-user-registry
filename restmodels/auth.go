package restmodels

// RegisterRequest is the payload to self-register a new User. Registration
// also creates a Group owned and administered by the new User.
type RegisterRequest struct {
	Username string `json:"username" minLength:"1" maxLength:"255"`
	Password string `json:"password" minLength:"8"`
	Name     string `json:"name" minLength:"1" maxLength:"255"`
	Surname  string `json:"surname" minLength:"1" maxLength:"255"`
	Email    string `json:"email" format:"email"`
}

type LoginRequest struct {
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
}

type LoginResponse struct {
	UseToken string `json:"use-token"`
}

// RequestPasswordResetRequest is the payload to trigger a password reset
// email. The response is identical regardless of whether the email is
// registered, to avoid leaking which addresses have accounts.
type RequestPasswordResetRequest struct {
	Email string `json:"email" format:"email"`
}

// ResetPasswordRequest redeems a password reset token, sent by email, for a
// new password.
type ResetPasswordRequest struct {
	Token       string `json:"token" minLength:"1"`
	NewPassword string `json:"newPassword" minLength:"8"`
}
