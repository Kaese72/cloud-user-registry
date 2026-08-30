package persistence

import "context"

type User struct {
	ID           int64
	Username     string
	Name         string
	Surname      string
	Email        string
	PasswordHash string
}

type Group struct {
	ID   int64
	Name string
}

// Membership describes a User's roles within a Group. See the "Group-User
// link" model in the README: admin can manage other members, owner is the
// group creator and can not be demoted or removed.
type Membership struct {
	Admin bool
	Owner bool
}

type GroupMembership struct {
	Group
	Membership
}

type GroupMember struct {
	User
	Membership
}

// Invitation is a pending offer for a User to join a Group, raised by an
// admin of that Group.
type Invitation struct {
	ID                int64
	GroupID           int64
	GroupName         string
	UserID            int64
	InvitedByUserID   int64
	InvitedByUsername string
}

// AuthPersistenceDB backs login and group-switching: resolving credentials
// and checking whether a user is allowed to switch into a given group.
type AuthPersistenceDB interface {
	GetUserByUsername(ctx context.Context, username string) (User, error)
	// GetDefaultGroupIDForUser returns the group to embed in a freshly issued
	// use token when a user authenticates without already having one selected.
	GetDefaultGroupIDForUser(ctx context.Context, userID int64) (int64, error)
	GetMembership(ctx context.Context, groupID int64, userID int64) (Membership, error)
}

// RegistrationPersistenceDB backs the self-registration flow: creating a
// user and their own admin+owner group in a single transaction.
type RegistrationPersistenceDB interface {
	RegisterUserWithOwnedGroup(ctx context.Context, username, passwordHash, name, surname, email, groupName string) (userID int64, groupID int64, err error)
}

type UserPersistenceDB interface {
	GetUserByID(ctx context.Context, id int64) (User, error)
	UpdateUser(ctx context.Context, id int64, name, surname, email string) error
	UpdatePassword(ctx context.Context, id int64, passwordHash string) error
}

// GroupPersistenceDB backs group management: listing groups a user belongs
// to, and administering the members of one specific group.
type GroupPersistenceDB interface {
	ListGroupsForUser(ctx context.Context, userID int64) ([]GroupMembership, error)
	GetGroup(ctx context.Context, groupID int64) (Group, error)
	GetMembership(ctx context.Context, groupID int64, userID int64) (Membership, error)
	UpdateGroupName(ctx context.Context, groupID int64, name string) error
	ListGroupMembers(ctx context.Context, groupID int64) ([]GroupMember, error)
	// SetMemberAdmin sets the admin flag of a member. It is a no-op error
	// path to attempt this on the group's owner; callers should check
	// Membership.Owner first for a clear error message.
	SetMemberAdmin(ctx context.Context, groupID int64, userID int64, admin bool) error
	// RemoveMember removes a member from a group. As with SetMemberAdmin,
	// callers should reject attempts to remove the owner before calling this.
	RemoveMember(ctx context.Context, groupID int64, userID int64) error
}

// InvitationPersistenceDB backs inviting existing users into a group and
// the invited user's accept/decline flow.
type InvitationPersistenceDB interface {
	GetUserByUsername(ctx context.Context, username string) (User, error)
	CreateInvitation(ctx context.Context, groupID int64, userID int64, invitedByUserID int64) (int64, error)
	ListInvitationsForUser(ctx context.Context, userID int64) ([]Invitation, error)
	GetInvitation(ctx context.Context, invitationID int64) (Invitation, error)
	AcceptInvitation(ctx context.Context, invitationID int64, userID int64) error
	DeclineInvitation(ctx context.Context, invitationID int64, userID int64) error
}
