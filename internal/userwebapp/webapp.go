package userwebapp

import (
	"context"
	"crypto/rsa"
	"database/sql"

	"github.com/Kaese72/cloud-user-registry/internal/logging"
	"github.com/Kaese72/cloud-user-registry/internal/persistence"
	"github.com/Kaese72/cloud-user-registry/internal/tokens"
	"github.com/Kaese72/cloud-user-registry/internal/validate"
	"github.com/Kaese72/cloud-user-registry/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type webApp struct {
	persistence persistence.UserPersistenceDB
	publicKey   *rsa.PublicKey
}

func NewWebApp(p persistence.UserPersistenceDB, publicKey *rsa.PublicKey) webApp {
	return webApp{persistence: p, publicKey: publicKey}
}

func toUserResponse(user persistence.User) restmodels.UserResponse {
	return restmodels.UserResponse{ID: user.ID, Username: user.Username, Name: user.Name, Surname: user.Surname, Email: user.Email}
}

func (app webApp) GetMe(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	userID, _, err := tokens.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	user, err := app.persistence.GetUserByID(ctx, userID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: toUserResponse(user)}, nil
}

func (app webApp) UpdateMe(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	Body          restmodels.UpdateUserRequest
}) (*struct {
	Body restmodels.UserResponse
}, error) {
	userID, _, err := tokens.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	if err := validate.Email(input.Body.Email); err != nil {
		return nil, huma.Error400BadRequest("invalid email address")
	}
	if err := app.persistence.UpdateUser(ctx, userID, input.Body.Name, input.Body.Surname, input.Body.Email); err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			return nil, huma.Error409Conflict("email already in use")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update user")
	}
	user, err := app.persistence.GetUserByID(ctx, userID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to retrieve updated user")
	}
	return &struct{ Body restmodels.UserResponse }{Body: toUserResponse(user)}, nil
}

func (app webApp) UpdateMyPassword(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	Body          restmodels.ChangePasswordRequest
}) (*struct{}, error) {
	userID, _, err := tokens.FromAuthHeader(app.publicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	user, err := app.persistence.GetUserByID(ctx, userID)
	if err == sql.ErrNoRows {
		return nil, huma.Error404NotFound("user not found")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to get user")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Body.CurrentPassword)); err != nil {
		return nil, huma.Error401Unauthorized("current password is incorrect")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to hash password")
	}
	if err := app.persistence.UpdatePassword(ctx, userID, string(hash)); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update password")
	}
	return &struct{}{}, nil
}
