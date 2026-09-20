package groupwebapp

import (
	"context"
	"crypto/rsa"
	"database/sql"

	"github.com/Kaese72/cloud-user-registry/cloudtoken"
	"github.com/Kaese72/cloud-user-registry/internal/logging"
	"github.com/Kaese72/cloud-user-registry/internal/persistence"
	"github.com/Kaese72/cloud-user-registry/restmodels"
	"github.com/danielgtaylor/huma/v2"
)

type persistenceDB interface {
	persistence.GroupPersistenceDB
	persistence.InvitationPersistenceDB
}

type webApp struct {
	persistence persistenceDB
	publicKey   *rsa.PublicKey
}

func NewWebApp(p persistenceDB, publicKey *rsa.PublicKey) webApp {
	return webApp{persistence: p, publicKey: publicKey}
}

func (app webApp) authenticate(authHeader string) (userID int64, groupID int64, err error) {
	return cloudtoken.FromAuthHeader(app.publicKey, authHeader)
}

// requireAdmin fetches the caller's membership in groupID and rejects the
// request unless they are an admin (owners are always admins too).
func (app webApp) requireAdmin(ctx context.Context, groupID int64, userID int64) error {
	membership, err := app.persistence.GetMembership(ctx, groupID, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return huma.Error403Forbidden("not a member of this group")
		}
		logging.ErrorErr(err, ctx)
		return huma.Error500InternalServerError("failed to verify group membership")
	}
	if !membership.Admin {
		return huma.Error403Forbidden("must be an admin of this group")
	}
	return nil
}

func toGroupResponse(gm persistence.GroupMembership) restmodels.GroupResponse {
	return restmodels.GroupResponse{ID: gm.ID, Name: gm.Name, Admin: gm.Admin, Owner: gm.Owner}
}

func toGroupMemberResponse(member persistence.GroupMember) restmodels.GroupMemberResponse {
	return restmodels.GroupMemberResponse{
		UserID: member.ID, Username: member.Username, Name: member.Name, Surname: member.Surname,
		Admin: member.Admin, Owner: member.Owner,
	}
}

func toInvitationResponse(invitation persistence.Invitation) restmodels.InvitationResponse {
	return restmodels.InvitationResponse{
		ID: invitation.ID, GroupID: invitation.GroupID, GroupName: invitation.GroupName,
		InvitedByUserID: invitation.InvitedByUserID, InvitedByUsername: invitation.InvitedByUsername,
	}
}

// ListMyGroups lists every Group the caller belongs to, along with their
// role in each - the set a client would offer when switching active group.
func (app webApp) ListMyGroups(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
}) (*struct {
	Body []restmodels.GroupResponse
}, error) {
	userID, _, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	memberships, err := app.persistence.ListGroupsForUser(ctx, userID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list groups")
	}
	resp := make([]restmodels.GroupResponse, len(memberships))
	for i, gm := range memberships {
		resp[i] = toGroupResponse(gm)
	}
	return &struct{ Body []restmodels.GroupResponse }{Body: resp}, nil
}

// GetCurrentGroup returns the Group the caller is currently interacting
// with, i.e. the one embedded in their use token.
func (app webApp) GetCurrentGroup(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
}) (*struct {
	Body restmodels.GroupResponse
}, error) {
	userID, groupID, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	group, err := app.persistence.GetGroup(ctx, groupID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get group")
	}
	membership, err := app.persistence.GetMembership(ctx, groupID, userID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify group membership")
	}
	return &struct{ Body restmodels.GroupResponse }{Body: restmodels.GroupResponse{ID: group.ID, Name: group.Name, Admin: membership.Admin, Owner: membership.Owner}}, nil
}

func (app webApp) UpdateCurrentGroup(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	Body          restmodels.UpdateGroupRequest
}) (*struct {
	Body restmodels.GroupResponse
}, error) {
	userID, groupID, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	if err := app.requireAdmin(ctx, groupID, userID); err != nil {
		return nil, err
	}
	if err := app.persistence.UpdateGroupName(ctx, groupID, input.Body.Name); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update group")
	}
	group, err := app.persistence.GetGroup(ctx, groupID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to retrieve updated group")
	}
	membership, err := app.persistence.GetMembership(ctx, groupID, userID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify group membership")
	}
	return &struct{ Body restmodels.GroupResponse }{Body: restmodels.GroupResponse{ID: group.ID, Name: group.Name, Admin: membership.Admin, Owner: membership.Owner}}, nil
}

func (app webApp) ListCurrentGroupMembers(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
}) (*struct {
	Body []restmodels.GroupMemberResponse
}, error) {
	_, groupID, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	members, err := app.persistence.ListGroupMembers(ctx, groupID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list group members")
	}
	resp := make([]restmodels.GroupMemberResponse, len(members))
	for i, member := range members {
		resp[i] = toGroupMemberResponse(member)
	}
	return &struct {
		Body []restmodels.GroupMemberResponse
	}{Body: resp}, nil
}

// SetMemberAdmin promotes or demotes another member's admin flag. Only
// admins may do this, and the owner's admin flag can never be changed.
func (app webApp) SetMemberAdmin(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	UserID        int64  `path:"userId"`
	Body          restmodels.SetMemberAdminRequest
}) (*struct{}, error) {
	callerID, groupID, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	if err := app.requireAdmin(ctx, groupID, callerID); err != nil {
		return nil, err
	}
	targetMembership, err := app.persistence.GetMembership(ctx, groupID, input.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("user is not a member of this group")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify group membership")
	}
	if targetMembership.Owner {
		return nil, huma.Error400BadRequest("the group owner's admin status can not be changed")
	}
	if err := app.persistence.SetMemberAdmin(ctx, groupID, input.UserID, input.Body.Admin); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update member")
	}
	return &struct{}{}, nil
}

// RemoveMember removes a member from the caller's current group. Admins may
// remove any non-owner member; any member may remove themselves (leave),
// except the owner, who can never be removed.
func (app webApp) RemoveMember(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	UserID        int64  `path:"userId"`
}) (*struct{}, error) {
	callerID, groupID, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	targetMembership, err := app.persistence.GetMembership(ctx, groupID, input.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("user is not a member of this group")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify group membership")
	}
	if targetMembership.Owner {
		return nil, huma.Error400BadRequest("the group owner can not be removed")
	}
	if input.UserID != callerID {
		if err := app.requireAdmin(ctx, groupID, callerID); err != nil {
			return nil, err
		}
	}
	if err := app.persistence.RemoveMember(ctx, groupID, input.UserID); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to remove member")
	}
	return &struct{}{}, nil
}

// CreateInvitation lets an admin of the caller's current group invite an
// existing User (by username) to join it.
func (app webApp) CreateInvitation(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	Body          restmodels.CreateInvitationRequest
}) (*struct {
	Body restmodels.InvitationResponse
}, error) {
	callerID, groupID, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	if err := app.requireAdmin(ctx, groupID, callerID); err != nil {
		return nil, err
	}
	invitee, err := app.persistence.GetUserByUsername(ctx, input.Body.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("user not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up user")
	}
	if _, err := app.persistence.GetMembership(ctx, groupID, invitee.ID); err == nil {
		return nil, huma.Error409Conflict("user is already a member of this group")
	} else if err != sql.ErrNoRows {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify group membership")
	}
	invitationID, err := app.persistence.CreateInvitation(ctx, groupID, invitee.ID, callerID)
	if err != nil {
		return nil, huma.Error409Conflict("user already has a pending invitation to this group")
	}
	invitation, err := app.persistence.GetInvitation(ctx, invitationID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to retrieve created invitation")
	}
	return &struct{ Body restmodels.InvitationResponse }{Body: toInvitationResponse(invitation)}, nil
}

// ListMyInvitations lists pending invitations addressed to the caller,
// across all groups, regardless of which group they are currently in.
func (app webApp) ListMyInvitations(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
}) (*struct {
	Body []restmodels.InvitationResponse
}, error) {
	userID, _, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	invitations, err := app.persistence.ListInvitationsForUser(ctx, userID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to list invitations")
	}
	resp := make([]restmodels.InvitationResponse, len(invitations))
	for i, invitation := range invitations {
		resp[i] = toInvitationResponse(invitation)
	}
	return &struct {
		Body []restmodels.InvitationResponse
	}{Body: resp}, nil
}

func (app webApp) AcceptInvitation(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	InvitationID  int64  `path:"invitationId"`
}) (*struct{}, error) {
	userID, _, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	if err := app.persistence.AcceptInvitation(ctx, input.InvitationID, userID); err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("invitation not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to accept invitation")
	}
	return &struct{}{}, nil
}

func (app webApp) DeclineInvitation(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	InvitationID  int64  `path:"invitationId"`
}) (*struct{}, error) {
	userID, _, err := app.authenticate(input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	if err := app.persistence.DeclineInvitation(ctx, input.InvitationID, userID); err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error404NotFound("invitation not found")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to decline invitation")
	}
	return &struct{}{}, nil
}
