package authwebapp

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/Kaese72/cloud-user-registry/cloudtoken"
	"github.com/Kaese72/cloud-user-registry/internal/logging"
	"github.com/Kaese72/cloud-user-registry/internal/persistence"
	"github.com/Kaese72/cloud-user-registry/internal/tokens"
	"github.com/Kaese72/cloud-user-registry/internal/validate"
	"github.com/Kaese72/cloud-user-registry/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

const refreshCookieName = "refresh-token"
const refreshCookiePath = "/cloud-user-registry/v0/authentication/login"

type persistenceDB interface {
	persistence.AuthPersistenceDB
	persistence.RegistrationPersistenceDB
}

type webApp struct {
	persistence        persistenceDB
	privateKey         *rsa.PrivateKey
	refreshSecret      string
	useTokenExpiry     time.Duration
	refreshTokenExpiry time.Duration
}

func NewWebApp(p persistenceDB, privateKey *rsa.PrivateKey, refreshSecret string, useTokenExpiry time.Duration, refreshTokenExpiry time.Duration) webApp {
	return webApp{
		persistence:        p,
		privateKey:         privateKey,
		refreshSecret:      refreshSecret,
		useTokenExpiry:     useTokenExpiry,
		refreshTokenExpiry: refreshTokenExpiry,
	}
}

func (app webApp) buildRefreshCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   true,
		MaxAge:   int(app.refreshTokenExpiry.Seconds()),
		SameSite: http.SameSiteStrictMode,
	}
}

func (app webApp) issueTokenPair(userID int64, groupID int64) (useToken string, refreshToken string, err error) {
	useToken, err = cloudtoken.Sign(app.privateKey, userID, groupID, app.useTokenExpiry)
	if err != nil {
		return
	}
	refreshToken, err = tokens.GenerateRefreshToken(app.refreshSecret, userID, groupID, app.refreshTokenExpiry)
	return
}

type loginResult struct {
	SetCookie string `header:"Set-Cookie"`
	Body      restmodels.LoginResponse
}

// Register creates a new User and a Group they own and administer, then logs
// them in exactly as Login would.
func (app webApp) Register(ctx context.Context, input *struct {
	Body restmodels.RegisterRequest
}) (*loginResult, error) {
	if err := validate.Email(input.Body.Email); err != nil {
		return nil, huma.Error400BadRequest("invalid email address")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Body.Password), bcrypt.DefaultCost)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to hash password")
	}
	groupName := fmt.Sprintf("%s's Group", input.Body.Name)
	userID, groupID, err := app.persistence.RegisterUserWithOwnedGroup(ctx, input.Body.Username, string(hash), input.Body.Name, input.Body.Surname, input.Body.Email, groupName)
	if err != nil {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok && mysqlErr.Number == 1062 {
			return nil, huma.Error409Conflict("username or email already registered")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to register user")
	}
	useToken, refreshToken, err := app.issueTokenPair(userID, groupID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("token generation failed")
	}
	return &loginResult{
		SetCookie: app.buildRefreshCookie(refreshToken).String(),
		Body:      restmodels.LoginResponse{UseToken: useToken},
	}, nil
}

func (app webApp) Login(ctx context.Context, input *struct {
	CookieHeader string `header:"Cookie"`
	Body         *restmodels.LoginRequest
}) (*loginResult, error) {
	// Try refresh cookie first: this keeps the user in whichever group they
	// were last interacting with.
	fakeReq := &http.Request{Header: http.Header{"Cookie": []string{input.CookieHeader}}}
	if cookie, err := fakeReq.Cookie(refreshCookieName); err == nil {
		userID, groupID, err := tokens.ValidateRefreshToken(app.refreshSecret, cookie.Value)
		if err == nil {
			useToken, refreshToken, err := app.issueTokenPair(userID, groupID)
			if err != nil {
				logging.ErrorErr(err, ctx)
				return nil, huma.Error500InternalServerError("token generation failed")
			}
			return &loginResult{
				SetCookie: app.buildRefreshCookie(refreshToken).String(),
				Body:      restmodels.LoginResponse{UseToken: useToken},
			}, nil
		}
	}

	// Fall back to username/password
	var username, password string
	if input.Body != nil && input.Body.Username != nil {
		username = *input.Body.Username
	}
	if input.Body != nil && input.Body.Password != nil {
		password = *input.Body.Password
	}
	if username == "" || password == "" {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	user, err := app.persistence.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}
	groupID, err := app.persistence.GetDefaultGroupIDForUser(ctx, user.ID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to determine active group")
	}

	useToken, refreshToken, err := app.issueTokenPair(user.ID, groupID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("token generation failed")
	}
	return &loginResult{
		SetCookie: app.buildRefreshCookie(refreshToken).String(),
		Body:      restmodels.LoginResponse{UseToken: useToken},
	}, nil
}

// SelectGroup re-issues the token pair scoped to a different Group the
// caller is a member of, implementing "actively switch between [groups]
// whenever" from the README.
func (app webApp) SelectGroup(ctx context.Context, input *struct {
	Authorization string `header:"Authorization"`
	GroupID       int64  `path:"groupId"`
}) (*loginResult, error) {
	userID, _, err := cloudtoken.FromAuthHeader(&app.privateKey.PublicKey, input.Authorization)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired token")
	}
	if _, err := app.persistence.GetMembership(ctx, input.GroupID, userID); err != nil {
		if err == sql.ErrNoRows {
			return nil, huma.Error403Forbidden("not a member of this group")
		}
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to verify group membership")
	}
	useToken, refreshToken, err := app.issueTokenPair(userID, input.GroupID)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("token generation failed")
	}
	return &loginResult{
		SetCookie: app.buildRefreshCookie(refreshToken).String(),
		Body:      restmodels.LoginResponse{UseToken: useToken},
	}, nil
}
