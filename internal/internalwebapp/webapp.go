// Package internalwebapp holds endpoints meant for other cloud services,
// authenticated with a static service token instead of a user's use token.
package internalwebapp

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"strings"

	"github.com/Kaese72/cloud-user-registry/internal/logging"
	"github.com/Kaese72/cloud-user-registry/internal/persistence"
	"github.com/Kaese72/cloud-user-registry/restmodels"
	"github.com/danielgtaylor/huma/v2"
)

type persistenceDB interface {
	GetUserByID(ctx context.Context, id int64) (persistence.User, error)
	GetMembership(ctx context.Context, groupID int64, userID int64) (persistence.Membership, error)
}

type webApp struct {
	persistence   persistenceDB
	serviceTokens []string
}

func NewWebApp(p persistenceDB, serviceTokens []string) webApp {
	return webApp{persistence: p, serviceTokens: serviceTokens}
}

// ParseTokenList splits a comma-separated config value into the set of
// currently-valid service tokens. More than one may be valid at once so a
// token can be rotated without a synchronized cutover.
func ParseTokenList(raw string) []string {
	var out []string
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (app webApp) checkServiceToken(authHeader string) bool {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	for _, configured := range app.serviceTokens {
		if subtle.ConstantTimeCompare([]byte(provided), []byte(configured)) == 1 {
			return true
		}
	}
	return false
}

// GetGroupMember reports whether userId is currently a member of groupId,
// returning the user's profile when they are. Callers use it both to
// establish a cloud user's identity at login and to re-check that access has
// not been revoked since.
func (app webApp) GetGroupMember(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	GroupID       int64  `path:"groupId"`
	UserID        int64  `path:"userId"`
}) (*struct {
	Body restmodels.MemberAccessResponse
}, error) {
	if !app.checkServiceToken(input.Authorization) {
		return nil, huma.Error401Unauthorized("invalid service token")
	}
	if _, err := app.persistence.GetMembership(ctx, input.GroupID, input.UserID); err != nil {
		if err == sql.ErrNoRows {
			return &struct {
				Body restmodels.MemberAccessResponse
			}{Body: restmodels.MemberAccessResponse{IsMember: false}}, nil
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify group membership")
	}
	user, err := app.persistence.GetUserByID(ctx, input.UserID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	return &struct {
		Body restmodels.MemberAccessResponse
	}{Body: restmodels.MemberAccessResponse{
		IsMember: true,
		User: &restmodels.UserResponse{
			ID: user.ID, Username: user.Username, Name: user.Name, Surname: user.Surname, Email: user.Email,
		},
	}}, nil
}
