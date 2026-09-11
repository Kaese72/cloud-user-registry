package persistence

import (
	"context"
	"time"
)

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

// PasswordResetPersistenceDB backs the "forgot password" flow: issuing a
// single-use reset token for a user found by email, and redeeming it once
// for a new password.
type PasswordResetPersistenceDB interface {
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id int64) (User, error)
	// CreatePasswordReset stores the hash of a freshly issued reset token.
	// The raw token itself is never persisted.
	CreatePasswordReset(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error
	// GetPasswordResetByTokenHash returns the reset record for a token
	// hash, regardless of whether it has expired or already been used;
	// callers are expected to check both before honoring it.
	GetPasswordResetByTokenHash(ctx context.Context, tokenHash string) (PasswordReset, error)
	// MarkPasswordResetUsed consumes a reset token so it can not be reused.
	MarkPasswordResetUsed(ctx context.Context, id int64) error
	UpdatePassword(ctx context.Context, id int64, passwordHash string) error
}

// PasswordReset is a pending offer for userId to set a new password,
// redeemable once before expiresAt.
type PasswordReset struct {
	ID        int64
	UserID    int64
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
}
