package restmodels

// GroupResponse describes a Group along with the calling User's roles in it.
type GroupResponse struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	Owner bool   `json:"owner"`
}

type UpdateGroupRequest struct {
	Name string `json:"name" minLength:"1" maxLength:"255"`
}

type GroupMemberResponse struct {
	UserID   int64  `json:"userId"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Admin    bool   `json:"admin"`
	Owner    bool   `json:"owner"`
}

type SetMemberAdminRequest struct {
	Admin bool `json:"admin"`
}
