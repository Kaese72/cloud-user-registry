package restmodels

type UserResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Email    string `json:"email"`
}

type UpdateUserRequest struct {
	Name    string `json:"name" minLength:"1" maxLength:"255"`
	Surname string `json:"surname" minLength:"1" maxLength:"255"`
	Email   string `json:"email" format:"email"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword" minLength:"8"`
}
