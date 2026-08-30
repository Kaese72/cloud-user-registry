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
