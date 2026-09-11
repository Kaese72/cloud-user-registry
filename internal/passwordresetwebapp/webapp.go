// Package passwordresetwebapp implements the "forgot password" flow: an
// unauthenticated caller requests a reset by email, gets a single-use,
// short-lived token emailed to them, and redeems that token for a new
// password.
package passwordresetwebapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Kaese72/cloud-user-registry/internal/config"
	"github.com/Kaese72/cloud-user-registry/internal/logging"
	"github.com/Kaese72/cloud-user-registry/internal/mailer"
	"github.com/Kaese72/cloud-user-registry/internal/persistence"
	"github.com/Kaese72/cloud-user-registry/restmodels"
	"github.com/danielgtaylor/huma/v2"
	"golang.org/x/crypto/bcrypt"
)

type webApp struct {
	persistence  persistence.PasswordResetPersistenceDB
	mailer       mailer.Mailer
	tokenExpiry  time.Duration
	resetURLBase string
}

func NewWebApp(p persistence.PasswordResetPersistenceDB, m mailer.Mailer, conf config.PasswordResetConfig) webApp {
	return webApp{
		persistence:  p,
		mailer:       m,
		tokenExpiry:  time.Duration(conf.TokenExpiryMinutes) * time.Minute,
		resetURLBase: conf.URLBase,
	}
}

func newToken() (raw string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash, nil
}

// RequestReset emails a reset link when the given address matches a
// registered user. The response is the same either way, so this endpoint
// can not be used to discover which emails have accounts.
func (app webApp) RequestReset(ctx context.Context, input *struct {
	Body restmodels.RequestPasswordResetRequest
}) (*struct{}, error) {
	user, err := app.persistence.GetUserByEmail(ctx, input.Body.Email)
	if err == sql.ErrNoRows {
		return &struct{}{}, nil
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up user")
	}

	raw, hash, err := newToken()
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to generate reset token")
	}
	if err := app.persistence.CreatePasswordReset(ctx, user.ID, hash, time.Now().Add(app.tokenExpiry)); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to store reset token")
	}

	resetURL := fmt.Sprintf("%s?token=%s", app.resetURLBase, raw)
	if err := app.mailer.SendPasswordReset(user.Email, resetURL); err != nil {
		// The token exists regardless; log but do not reveal delivery
		// failures to the caller, for the same reason we don't reveal
		// whether the address was registered.
		logging.ErrorErr(err, ctx)
	}
	return &struct{}{}, nil
}

// ConfirmReset redeems a reset token for a new password. Tokens are
// single-use and expire after the configured window.
func (app webApp) ConfirmReset(ctx context.Context, input *struct {
	Body restmodels.ResetPasswordRequest
}) (*struct{}, error) {
	sum := sha256.Sum256([]byte(input.Body.Token))
	hash := hex.EncodeToString(sum[:])

	reset, err := app.persistence.GetPasswordResetByTokenHash(ctx, hash)
	if err == sql.ErrNoRows {
		return nil, huma.Error400BadRequest("invalid or expired reset token")
	}
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to look up reset token")
	}
	if reset.UsedAt != nil || time.Now().After(reset.ExpiresAt) {
		return nil, huma.Error400BadRequest("invalid or expired reset token")
	}
	// Constant-time comparison isn't strictly needed here (the hash was
	// already looked up by exact match), but guards against any future
	// change to a non-indexed lookup.
	if subtle.ConstantTimeCompare([]byte(reset.TokenHash), []byte(hash)) != 1 {
		return nil, huma.Error400BadRequest("invalid or expired reset token")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to hash password")
	}
	if err := app.persistence.UpdatePassword(ctx, reset.UserID, string(hashedPassword)); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to update password")
	}
	if err := app.persistence.MarkPasswordResetUsed(ctx, reset.ID); err != nil {
		logging.ErrorErr(err, ctx)
		return nil, huma.Error500InternalServerError("failed to consume reset token")
	}
	return &struct{}{}, nil
}
