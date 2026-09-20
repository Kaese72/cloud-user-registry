package internalwebapp

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"

	"github.com/Kaese72/cloud-user-registry/internal/persistence"
	"github.com/danielgtaylor/huma/v2"
)

type fakeDB struct {
	members map[[2]int64]bool
	users   map[int64]persistence.User
	err     error
}

func (d fakeDB) GetUserByID(_ context.Context, id int64) (persistence.User, error) {
	if u, ok := d.users[id]; ok {
		return u, nil
	}
	return persistence.User{}, sql.ErrNoRows
}

func (d fakeDB) GetMembership(_ context.Context, groupID int64, userID int64) (persistence.Membership, error) {
	if d.err != nil {
		return persistence.Membership{}, d.err
	}
	if d.members[[2]int64{groupID, userID}] {
		return persistence.Membership{}, nil
	}
	return persistence.Membership{}, sql.ErrNoRows
}

type input = struct {
	Authorization string `header:"Authorization"`
	GroupID       int64  `path:"groupId"`
	UserID        int64  `path:"userId"`
}

func newApp() webApp {
	return NewWebApp(fakeDB{
		members: map[[2]int64]bool{{10, 7}: true},
		users:   map[int64]persistence.User{7: {ID: 7, Username: "alice", Name: "Alice", Surname: "A", Email: "a@example.com"}},
	}, ParseTokenList(" old-token , new-token,"))
}

func statusOf(err error) int {
	var se huma.StatusError
	if errors.As(err, &se) {
		return se.GetStatus()
	}
	return 0
}

func TestRequiresServiceToken(t *testing.T) {
	for name, header := range map[string]string{
		"missing":      "",
		"wrong":        "Bearer nope",
		"not a bearer": "old-token",
		"empty bearer": "Bearer ",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newApp().GetGroupMember(context.Background(), &input{Authorization: header, GroupID: 10, UserID: 7})
			if statusOf(err) != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %v", err)
			}
		})
	}
}

func TestAnyConfiguredTokenIsAccepted(t *testing.T) {
	for _, token := range []string{"old-token", "new-token"} {
		res, err := newApp().GetGroupMember(context.Background(), &input{Authorization: "Bearer " + token, GroupID: 10, UserID: 7})
		if err != nil || !res.Body.IsMember {
			t.Fatalf("token %q should be accepted, got %v", token, err)
		}
	}
}

func TestMemberGetsProfileNonMemberDoesNot(t *testing.T) {
	res, err := newApp().GetGroupMember(context.Background(), &input{Authorization: "Bearer old-token", GroupID: 10, UserID: 7})
	if err != nil || !res.Body.IsMember || res.Body.User == nil || res.Body.User.Username != "alice" {
		t.Fatalf("expected alice as a member, got %+v %v", res, err)
	}

	res, err = newApp().GetGroupMember(context.Background(), &input{Authorization: "Bearer old-token", GroupID: 11, UserID: 7})
	if err != nil || res.Body.IsMember || res.Body.User != nil {
		t.Fatalf("membership is per group; expected a non-member with no profile, got %+v %v", res, err)
	}
}

func TestDatabaseErrorIsNotReportedAsNonMember(t *testing.T) {
	app := NewWebApp(fakeDB{err: errors.New("db down")}, []string{"t"})
	_, err := app.GetGroupMember(context.Background(), &input{Authorization: "Bearer t", GroupID: 10, UserID: 7})
	if statusOf(err) != http.StatusInternalServerError {
		t.Fatalf("a failure to look up membership must not read as \"not a member\", got %v", err)
	}
}
