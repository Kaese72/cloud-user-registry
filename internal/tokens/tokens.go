// Package tokens holds the parts of token handling that are private to this
// service: parsing its RSA private key and generating/validating the
// "refresh" JWT, which is exchanged for a fresh token pair without
// re-entering credentials.
//
// The "use" token, the one every other service verifies, is defined in the
// public cloudtoken package instead, so its format has a single owner that
// other services can import rather than re-implement.
//
// See the "Authentication architecture" section of the authentication
// service's README for the general use/refresh token model this mirrors;
// the only difference here is that tokens additionally carry a groupId,
// since users can belong to (and switch between) multiple groups.
package tokens

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/Kaese72/cloud-user-registry/cloudtoken"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

// ParseRSAPrivateKey decodes a PEM-encoded RSA private key in either PKCS1
// ("RSA PRIVATE KEY") or PKCS8 ("PRIVATE KEY") form.
func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func GenerateRefreshToken(secret string, userID int64, groupID int64, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		cloudtoken.ClaimUserID:  userID,
		cloudtoken.ClaimGroupID: groupID,
		"exp":                   time.Now().Add(expiry).Unix(),
		"iat":                   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func claimsToIdentity(claims jwt.MapClaims) (userID int64, groupID int64, err error) {
	idFloat, ok := claims[cloudtoken.ClaimUserID].(float64)
	if !ok {
		return 0, 0, errors.New("invalid id claim")
	}
	groupIDFloat, ok := claims[cloudtoken.ClaimGroupID].(float64)
	if !ok {
		return 0, 0, errors.New("invalid groupId claim")
	}
	return int64(idFloat), int64(groupIDFloat), nil
}

// ValidateRefreshToken verifies the HS256 signature of a refresh token and
// returns the userId and groupId embedded in it.
func ValidateRefreshToken(secret string, tokenString string) (userID int64, groupID int64, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return 0, 0, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, 0, errors.New("invalid token")
	}
	return claimsToIdentity(claims)
}
