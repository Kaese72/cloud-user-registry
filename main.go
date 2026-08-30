package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Kaese72/cloud-user-registry/internal/authwebapp"
	"github.com/Kaese72/cloud-user-registry/internal/config"
	"github.com/Kaese72/cloud-user-registry/internal/groupwebapp"
	"github.com/Kaese72/cloud-user-registry/internal/logging"
	"github.com/Kaese72/cloud-user-registry/internal/persistence/mariadb"
	"github.com/Kaese72/cloud-user-registry/internal/tokens"
	"github.com/Kaese72/cloud-user-registry/internal/userwebapp"
	"github.com/Kaese72/huemie-lib/middleware"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humamux"
	"github.com/gorilla/mux"

	_ "go.elastic.co/apm/module/apmsql/mysql"
)

func main() {
	if err := config.Loaded.Validate(); err != nil {
		logging.Error(err.Error(), context.TODO())
		os.Exit(1)
	}

	dbPersistence, err := mariadb.NewMariadbPersistence(config.Loaded.Database)
	if err != nil {
		logging.Error(err.Error(), context.Background())
		os.Exit(1)
	}

	keyBytes, err := os.ReadFile(config.Loaded.Auth.RSAPrivateKeyPath)
	if err != nil {
		logging.Error("failed to read RSA private key: "+err.Error(), context.Background())
		os.Exit(1)
	}
	privateKey, err := tokens.ParseRSAPrivateKey(keyBytes)
	if err != nil {
		logging.Error("failed to parse RSA private key: "+err.Error(), context.Background())
		os.Exit(1)
	}

	useTokenExpiry := time.Duration(config.Loaded.Auth.UseTokenExpiryMinutes) * time.Minute
	refreshTokenExpiry := time.Duration(config.Loaded.Auth.RefreshTokenExpiryDays) * 24 * time.Hour

	authApp := authwebapp.NewWebApp(dbPersistence, privateKey, config.Loaded.Auth.RefreshSecret, useTokenExpiry, refreshTokenExpiry)
	userApp := userwebapp.NewWebApp(dbPersistence, &privateKey.PublicKey)
	groupApp := groupwebapp.NewWebApp(dbPersistence, &privateKey.PublicKey)

	router := mux.NewRouter()
	router.Use(middleware.UseTokenMiddleware(
		&privateKey.PublicKey,
		"/cloud-user-registry/v0/registration",
		"/cloud-user-registry/v0/authentication/login",
		"/cloud-user-registry/docs",
		"/cloud-user-registry/openapi",
	))
	humaConfig := huma.DefaultConfig("cloud-user-registry", "1.0.0")
	humaConfig.OpenAPIPath = "/cloud-user-registry/openapi"
	humaConfig.DocsPath = "/cloud-user-registry/docs"
	api := humamux.New(router, humaConfig)

	huma.Post(api, "/cloud-user-registry/v0/registration", authApp.Register)
	huma.Post(api, "/cloud-user-registry/v0/authentication/login", authApp.Login)
	huma.Post(api, "/cloud-user-registry/v0/groups/{groupId:[0-9]+}/select", authApp.SelectGroup)

	huma.Get(api, "/cloud-user-registry/v0/users/me", userApp.GetMe)
	huma.Put(api, "/cloud-user-registry/v0/users/me", userApp.UpdateMe)
	huma.Put(api, "/cloud-user-registry/v0/users/me/password", userApp.UpdateMyPassword)

	huma.Get(api, "/cloud-user-registry/v0/groups", groupApp.ListMyGroups)
	huma.Get(api, "/cloud-user-registry/v0/groups/current", groupApp.GetCurrentGroup)
	huma.Patch(api, "/cloud-user-registry/v0/groups/current", groupApp.UpdateCurrentGroup)
	huma.Get(api, "/cloud-user-registry/v0/groups/current/members", groupApp.ListCurrentGroupMembers)
	huma.Put(api, "/cloud-user-registry/v0/groups/current/members/{userId:[0-9]+}/admin", groupApp.SetMemberAdmin)
	huma.Delete(api, "/cloud-user-registry/v0/groups/current/members/{userId:[0-9]+}", groupApp.RemoveMember)

	huma.Post(api, "/cloud-user-registry/v0/groups/current/invitations", groupApp.CreateInvitation)
	huma.Get(api, "/cloud-user-registry/v0/invitations", groupApp.ListMyInvitations)
	huma.Post(api, "/cloud-user-registry/v0/invitations/{invitationId:[0-9]+}/accept", groupApp.AcceptInvitation)
	huma.Post(api, "/cloud-user-registry/v0/invitations/{invitationId:[0-9]+}/decline", groupApp.DeclineInvitation)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", config.Loaded.Port), router); err != nil {
		logging.Error(err.Error(), context.TODO())
	}
}
