package cloudtoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// rawToken signs arbitrary claims, bypassing Sign, to build tokens Sign would
// never produce.
func rawToken(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := newKey(t)
	token, err := Sign(key, 42, 7, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	userID, groupID, err := Verify(&key.PublicKey, token)
	if err != nil || userID != 42 || groupID != 7 {
		t.Fatalf("Verify = (%d, %d, %v), want (42, 7, nil)", userID, groupID, err)
	}
}

func TestVerifyRejects(t *testing.T) {
	key, other := newKey(t), newKey(t)
	exp := time.Now().Add(time.Minute).Unix()
	good := func(extra jwt.MapClaims) jwt.MapClaims {
		c := jwt.MapClaims{ClaimUserID: 1, ClaimGroupID: 1, "exp": exp}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	without := func(name string) jwt.MapClaims {
		c := good(nil)
		delete(c, name)
		return c
	}

	tests := map[string]string{
		"wrong key":          rawToken(t, jwt.SigningMethodRS256, other, good(nil)),
		"expired":            rawToken(t, jwt.SigningMethodRS256, key, good(jwt.MapClaims{"exp": time.Now().Add(-time.Minute).Unix()})),
		"no id":              rawToken(t, jwt.SigningMethodRS256, key, without(ClaimUserID)),
		"no groupId":         rawToken(t, jwt.SigningMethodRS256, key, without(ClaimGroupID)),
		"non-numeric id":     rawToken(t, jwt.SigningMethodRS256, key, good(jwt.MapClaims{ClaimUserID: "abc"})),
		"non-numeric group":  rawToken(t, jwt.SigningMethodRS256, key, good(jwt.MapClaims{ClaimGroupID: "abc"})),
		"zero id":            rawToken(t, jwt.SigningMethodRS256, key, good(jwt.MapClaims{ClaimUserID: 0})),
		"zero groupId":       rawToken(t, jwt.SigningMethodRS256, key, good(jwt.MapClaims{ClaimGroupID: 0})),
		"negative id":        rawToken(t, jwt.SigningMethodRS256, key, good(jwt.MapClaims{ClaimUserID: -5})),
		"HMAC (refresh) one": rawToken(t, jwt.SigningMethodHS256, []byte("secret"), good(nil)),
		"not a token":        "nonsense",
		"empty":              "",
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if userID, groupID, err := Verify(&key.PublicKey, token); err == nil {
				t.Fatalf("Verify accepted it, returned (%d, %d)", userID, groupID)
			}
		})
	}
}

func TestFromAuthHeader(t *testing.T) {
	key := newKey(t)
	token, err := Sign(key, 3, 4, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if userID, groupID, err := FromAuthHeader(&key.PublicKey, "Bearer "+token); err != nil || userID != 3 || groupID != 4 {
		t.Fatalf("FromAuthHeader = (%d, %d, %v), want (3, 4, nil)", userID, groupID, err)
	}
	for name, header := range map[string]string{
		"empty":         "",
		"no scheme":     token,
		"wrong scheme":  "Basic " + token,
		"garbage token": "Bearer nonsense",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := FromAuthHeader(&key.PublicKey, header); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestMiddleware(t *testing.T) {
	key := newKey(t)
	valid, err := Sign(key, 42, 7, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	noGroup := rawToken(t, jwt.SigningMethodRS256, key, jwt.MapClaims{ClaimUserID: 42, "exp": time.Now().Add(time.Minute).Unix()})

	tests := []struct {
		name        string
		path        string
		auth        string
		wantStatus  int
		wantUser    int64
		wantGroup   int64
		wantHasInfo bool
	}{
		{"valid token exposes user and group", "/x", "Bearer " + valid, http.StatusOK, 42, 7, true},
		{"skipped prefix passes with no identity", "/docs/x", "", http.StatusOK, 0, 0, false},
		{"skipped prefix ignores a bad token", "/docs/x", "Bearer nonsense", http.StatusOK, 0, 0, false},
		{"missing header", "/x", "", http.StatusUnauthorized, 0, 0, false},
		{"not a bearer header", "/x", "Basic abc", http.StatusUnauthorized, 0, 0, false},
		{"garbage token", "/x", "Bearer nonsense", http.StatusUnauthorized, 0, 0, false},
		{"validly signed but no groupId", "/x", "Bearer " + noGroup, http.StatusUnauthorized, 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				called          bool
				user, group     int64
				userOK, groupOK bool
			)
			h := Middleware(&key.PublicKey, "/docs")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				user, userOK = UserID(r.Context())
				group, groupOK = GroupID(r.Context())
			}))
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if called != (tc.wantStatus == http.StatusOK) {
				t.Fatalf("handler called = %v with status %d", called, rec.Code)
			}
			if user != tc.wantUser || group != tc.wantGroup || userOK != tc.wantHasInfo || groupOK != tc.wantHasInfo {
				t.Fatalf("UserID/GroupID = (%d,%v)/(%d,%v), want (%d,%v)/(%d,%v)",
					user, userOK, group, groupOK, tc.wantUser, tc.wantHasInfo, tc.wantGroup, tc.wantHasInfo)
			}
		})
	}
}

func pemBytes(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func TestParseAndLoadPublicKey(t *testing.T) {
	key := newKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid key verifies tokens", func(t *testing.T) {
		token, err := Sign(key, 7, 8, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ParsePublicKey(pemBytes("PUBLIC KEY", der))
		if err != nil {
			t.Fatal(err)
		}
		if u, g, err := Verify(pub, token); err != nil || u != 7 || g != 8 {
			t.Fatalf("Verify with parsed key = (%d, %d, %v), want (7, 8, nil)", u, g, err)
		}

		path := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(path, pemBytes("PUBLIC KEY", der), 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadPublicKeyFromFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if u, g, err := Verify(loaded, token); err != nil || u != 7 || g != 8 {
			t.Fatalf("Verify with loaded key = (%d, %d, %v), want (7, 8, nil)", u, g, err)
		}
	})

	for name, in := range map[string][]byte{
		"no PEM block":               []byte("not pem"),
		"PEM that is not a key":      pemBytes("PUBLIC KEY", []byte("garbage")),
		"non-RSA (ECDSA) public key": pemBytes("PUBLIC KEY", ecDER),
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, err := ParsePublicKey(in); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadPublicKeyFromFile(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
			t.Fatal("expected an error")
		}
	})
}
