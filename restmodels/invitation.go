package restmodels

// CreateInvitationRequest invites an existing User, identified by username,
// to join the caller's currently active Group.
type CreateInvitationRequest struct {
	Username string `json:"username" minLength:"1"`
}

type InvitationResponse struct {
	ID                int64  `json:"id"`
	GroupID           int64  `json:"groupId"`
	GroupName         string `json:"groupName"`
	InvitedByUserID   int64  `json:"invitedByUserId"`
	InvitedByUsername string `json:"invitedByUsername"`
}
