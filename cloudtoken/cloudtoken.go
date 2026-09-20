// Package cloudtoken is the single definition of the cloud-user-registry's
// `use` token: how it is signed, how it is verified, and what claims it
// carries. It is deliberately a public package of the cloud-user-registry
// module (not under internal/) so that other services can import it instead
// of re-implementing the token format.
//
// A cloud `use` token is an RS256 JWT carrying two identifying claims: "id",
// the ID of the authenticated user, and "groupId", the ID of the group the
// user is currently interacting with (users can belong to, and switch
// between, several groups). Services verify it locally against the
// cloud-user-registry's RSA public key; nothing here calls the
// cloud-user-registry.
//
// This is a different token from the authentication service's `use` token
// (see that service's usertoken package): that one is issued to users of a
// single appliance and has no group. The two are signed with different keys
// and must not be mixed up.
//
// The refresh token the cloud-user-registry also issues is deliberately not
// here. It is HS256-signed with a secret only the cloud-user-registry holds,
// so no other service ever verifies one.
//
// Deliberately only depends on the JWT library and huemie-lib's error
// formatting, so importing it does not pull the cloud-user-registry's own
// dependencies (database driver, SMTP, ...) into a consumer.
package cloudtoken

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Kaese72/huemie-lib/liberrors"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// ClaimUserID is the name of the claim holding the authenticated user's ID.
	ClaimUserID = "id"
	// ClaimGroupID is the name of the claim holding the ID of the group the
	// user is currently interacting with.
	ClaimGroupID = "groupId"
)

// ParsePublicKey decodes a PKIX PEM-encoded RSA public key, as published by
// the cloud-user-registry, for use with Verify, FromAuthHeader and
// Middleware.
func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("PEM block does not contain an RSA public key")
	}
	return rsaPub, nil
}

// LoadPublicKeyFromFile reads a PKIX PEM-encoded RSA public key from disk;
// see ParsePublicKey.
func LoadPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}
	pub, err := ParsePublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pub, nil
}

// Sign issues a use token for userID acting within groupID, valid for expiry.
// Only the cloud-user-registry, which holds the private key, should call
// this.
func Sign(privateKey *rsa.PrivateKey, userID int64, groupID int64, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		ClaimUserID:  userID,
		ClaimGroupID: groupID,
		"exp":        time.Now().Add(expiry).Unix(),
		"iat":        time.Now().Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
}

// Verify checks tokenString's RS256 signature and expiry against publicKey
// and returns the user and group it was issued for. A validly signed token
// without a usable (numeric, positive) id and groupId claim is rejected:
// every use token the cloud-user-registry issues has both, so their absence
// means the token is not a cloud use token. In particular, a refresh token
// (HS256) is rejected here by its signing method.
func Verify(publicKey *rsa.PublicKey, tokenString string) (userID int64, groupID int64, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return 0, 0, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, 0, errors.New("invalid token")
	}
	id, ok := claims[ClaimUserID].(float64)
	if !ok || id < 1 {
		return 0, 0, errors.New("invalid id claim")
	}
	group, ok := claims[ClaimGroupID].(float64)
	if !ok || group < 1 {
		return 0, 0, errors.New("invalid groupId claim")
	}
	return int64(id), int64(group), nil
}

// FromAuthHeader validates the bearer use token in an "Authorization" header
// value and returns the user and group embedded in it.
func FromAuthHeader(publicKey *rsa.PublicKey, authHeader string) (userID int64, groupID int64, err error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return 0, 0, errors.New("missing bearer token")
	}
	return Verify(publicKey, strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")))
}

type identityContextKey struct{}

type identity struct {
	userID  int64
	groupID int64
}

// UserID returns the authenticated caller's user ID, as placed in the request
// context by Middleware. It returns false if the request did not pass through
// Middleware, or matched one of its skipped prefixes.
func UserID(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(identityContextKey{}).(identity)
	return id.userID, ok
}

// GroupID returns the ID of the group the authenticated caller is currently
// acting within, with the same availability as UserID.
func GroupID(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(identityContextKey{}).(identity)
	return id.groupID, ok
}

// Middleware returns an HTTP middleware that requires a valid cloud use token
// as a bearer token and makes the caller's user and group available through
// UserID and GroupID. Requests whose path starts with any entry in
// skipPrefixes bypass authentication entirely (and so have no identity).
//
// The returned type is func(http.Handler) http.Handler, which is directly
// assignable to gorilla/mux's MiddlewareFunc without an explicit cast.
func Middleware(publicKey *rsa.PublicKey, skipPrefixes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range skipPrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				liberrors.NewApiError(liberrors.Unauthorized, errors.New("missing bearer token")).WriteHTTP(w)
				return
			}
			userID, groupID, err := FromAuthHeader(publicKey, authHeader)
			if err != nil {
				liberrors.NewApiError(liberrors.Unauthorized, errors.New("invalid or expired token")).WriteHTTP(w)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityContextKey{}, identity{userID: userID, groupID: groupID})))
		})
	}
}
