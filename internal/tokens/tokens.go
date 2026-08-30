// Package tokens generates and validates the "use" and "refresh" JWTs
// issued by this service. A "use" token authenticates a request and is
// scoped to the group the user is currently interacting with; a "refresh"
// token is exchanged for a fresh pair without re-entering credentials.
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
	"strings"
	"time"

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

func GenerateUseToken(privateKey *rsa.PrivateKey, userID int64, groupID int64, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"id":      userID,
		"groupId": groupID,
		"exp":     time.Now().Add(expiry).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func GenerateRefreshToken(secret string, userID int64, groupID int64, expiry time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"id":      userID,
		"groupId": groupID,
		"exp":     time.Now().Add(expiry).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func claimsToIdentity(claims jwt.MapClaims) (userID int64, groupID int64, err error) {
	idFloat, ok := claims["id"].(float64)
	if !ok {
		return 0, 0, errors.New("invalid id claim")
	}
	groupIDFloat, ok := claims["groupId"].(float64)
	if !ok {
		return 0, 0, errors.New("invalid groupId claim")
	}
	return int64(idFloat), int64(groupIDFloat), nil
}

// ValidateUseToken verifies the RS256 signature of a use token and returns
// the userId and groupId embedded in it.
func ValidateUseToken(publicKey *rsa.PublicKey, tokenString string) (userID int64, groupID int64, err error) {
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
	return claimsToIdentity(claims)
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

// FromAuthHeader validates the bearer use token in an "Authorization" header
// value and returns the userId and groupId embedded in it.
func FromAuthHeader(publicKey *rsa.PublicKey, authHeader string) (userID int64, groupID int64, err error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return 0, 0, errors.New("missing bearer token")
	}
	tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	return ValidateUseToken(publicKey, tokenString)
}
