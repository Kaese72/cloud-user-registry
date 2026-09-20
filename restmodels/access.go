package restmodels

// MemberAccessResponse answers "is this user currently a member of this
// group" for internal service callers (see internalwebapp). User is only set
// when IsMember is true.
type MemberAccessResponse struct {
	IsMember bool          `json:"isMember"`
	User     *UserResponse `json:"user,omitempty"`
}
