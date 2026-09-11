package mariadb

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Kaese72/cloud-user-registry/internal/config"
	"github.com/Kaese72/cloud-user-registry/internal/logging"
	"github.com/Kaese72/cloud-user-registry/internal/persistence"
	"go.elastic.co/apm/module/apmsql"
)

var (
	_ persistence.AuthPersistenceDB          = mariadbPersistence{}
	_ persistence.RegistrationPersistenceDB  = mariadbPersistence{}
	_ persistence.UserPersistenceDB          = mariadbPersistence{}
	_ persistence.GroupPersistenceDB         = mariadbPersistence{}
	_ persistence.InvitationPersistenceDB    = mariadbPersistence{}
	_ persistence.PasswordResetPersistenceDB = mariadbPersistence{}
)

type mariadbPersistence struct {
	db *sql.DB
}

func NewMariadbPersistence(conf config.DatabaseConfig) (mariadbPersistence, error) {
	db, err := apmsql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC", conf.User, conf.Password, conf.Host, conf.Port, conf.Database))
	if err != nil {
		logging.Fatal(err.Error(), context.Background())
		return mariadbPersistence{}, err
	}
	return mariadbPersistence{db: db}, nil
}

func (m mariadbPersistence) GetUserByUsername(ctx context.Context, username string) (persistence.User, error) {
	row := m.db.QueryRowContext(ctx, `SELECT id, username, name, surname, email, passwordHash FROM users WHERE username = ?`, username)
	var user persistence.User
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email, &user.PasswordHash); err != nil {
		return persistence.User{}, err
	}
	return user, nil
}

func (m mariadbPersistence) GetUserByID(ctx context.Context, id int64) (persistence.User, error) {
	row := m.db.QueryRowContext(ctx, `SELECT id, username, name, surname, email, passwordHash FROM users WHERE id = ?`, id)
	var user persistence.User
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email, &user.PasswordHash); err != nil {
		return persistence.User{}, err
	}
	return user, nil
}

func (m mariadbPersistence) UpdateUser(ctx context.Context, id int64, name, surname, email string) error {
	result, err := m.db.ExecContext(ctx, `UPDATE users SET name = ?, surname = ?, email = ? WHERE id = ?`, name, surname, email, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) UpdatePassword(ctx context.Context, id int64, passwordHash string) error {
	result, err := m.db.ExecContext(ctx, `UPDATE users SET passwordHash = ? WHERE id = ?`, passwordHash, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) GetDefaultGroupIDForUser(ctx context.Context, userID int64) (int64, error) {
	var groupID int64
	row := m.db.QueryRowContext(ctx, `SELECT groupId FROM groupUsers WHERE userId = ? ORDER BY groupId ASC LIMIT 1`, userID)
	if err := row.Scan(&groupID); err != nil {
		return 0, err
	}
	return groupID, nil
}

func (m mariadbPersistence) GetMembership(ctx context.Context, groupID int64, userID int64) (persistence.Membership, error) {
	var membership persistence.Membership
	row := m.db.QueryRowContext(ctx, `SELECT admin, owner FROM groupUsers WHERE groupId = ? AND userId = ?`, groupID, userID)
	if err := row.Scan(&membership.Admin, &membership.Owner); err != nil {
		return persistence.Membership{}, err
	}
	return membership, nil
}

func (m mariadbPersistence) RegisterUserWithOwnedGroup(ctx context.Context, username, passwordHash, name, surname, email, groupName string) (userID int64, groupID int64, err error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	userResult, err := tx.ExecContext(ctx, `INSERT INTO users (username, passwordHash, name, surname, email) VALUES (?, ?, ?, ?, ?)`, username, passwordHash, name, surname, email)
	if err != nil {
		return 0, 0, err
	}
	userID, err = userResult.LastInsertId()
	if err != nil {
		return 0, 0, err
	}

	groupResult, err := tx.ExecContext(ctx, `INSERT INTO groups (name) VALUES (?)`, groupName)
	if err != nil {
		return 0, 0, err
	}
	groupID, err = groupResult.LastInsertId()
	if err != nil {
		return 0, 0, err
	}

	if _, err = tx.ExecContext(ctx, `INSERT INTO groupUsers (groupId, userId, admin, owner) VALUES (?, ?, TRUE, TRUE)`, groupID, userID); err != nil {
		return 0, 0, err
	}

	return userID, groupID, tx.Commit()
}

func (m mariadbPersistence) ListGroupsForUser(ctx context.Context, userID int64) ([]persistence.GroupMembership, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT groups.id, groups.name, groupUsers.admin, groupUsers.owner
		FROM groupUsers
		INNER JOIN groups ON groups.id = groupUsers.groupId
		WHERE groupUsers.userId = ?
		ORDER BY groups.name ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	memberships := []persistence.GroupMembership{}
	for rows.Next() {
		var gm persistence.GroupMembership
		if err := rows.Scan(&gm.ID, &gm.Name, &gm.Admin, &gm.Owner); err != nil {
			return nil, err
		}
		memberships = append(memberships, gm)
	}
	return memberships, rows.Err()
}

func (m mariadbPersistence) GetGroup(ctx context.Context, groupID int64) (persistence.Group, error) {
	var group persistence.Group
	row := m.db.QueryRowContext(ctx, `SELECT id, name FROM groups WHERE id = ?`, groupID)
	if err := row.Scan(&group.ID, &group.Name); err != nil {
		return persistence.Group{}, err
	}
	return group, nil
}

func (m mariadbPersistence) UpdateGroupName(ctx context.Context, groupID int64, name string) error {
	result, err := m.db.ExecContext(ctx, `UPDATE groups SET name = ? WHERE id = ?`, name, groupID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) ListGroupMembers(ctx context.Context, groupID int64) ([]persistence.GroupMember, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT users.id, users.username, users.name, users.surname, users.email, groupUsers.admin, groupUsers.owner
		FROM groupUsers
		INNER JOIN users ON users.id = groupUsers.userId
		WHERE groupUsers.groupId = ?
		ORDER BY users.username ASC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	members := []persistence.GroupMember{}
	for rows.Next() {
		var member persistence.GroupMember
		if err := rows.Scan(&member.ID, &member.Username, &member.Name, &member.Surname, &member.Email, &member.Admin, &member.Owner); err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func (m mariadbPersistence) SetMemberAdmin(ctx context.Context, groupID int64, userID int64, admin bool) error {
	result, err := m.db.ExecContext(ctx, `UPDATE groupUsers SET admin = ? WHERE groupId = ? AND userId = ? AND owner = FALSE`, admin, groupID, userID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) RemoveMember(ctx context.Context, groupID int64, userID int64) error {
	result, err := m.db.ExecContext(ctx, `DELETE FROM groupUsers WHERE groupId = ? AND userId = ? AND owner = FALSE`, groupID, userID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) CreateInvitation(ctx context.Context, groupID int64, userID int64, invitedByUserID int64) (int64, error) {
	result, err := m.db.ExecContext(ctx, `INSERT INTO groupInvitations (groupId, userId, invitedBy) VALUES (?, ?, ?)`, groupID, userID, invitedByUserID)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (m mariadbPersistence) ListInvitationsForUser(ctx context.Context, userID int64) ([]persistence.Invitation, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT groupInvitations.id, groupInvitations.groupId, groups.name, groupInvitations.userId, groupInvitations.invitedBy, inviter.username
		FROM groupInvitations
		INNER JOIN groups ON groups.id = groupInvitations.groupId
		INNER JOIN users AS inviter ON inviter.id = groupInvitations.invitedBy
		WHERE groupInvitations.userId = ?
		ORDER BY groupInvitations.id ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	invitations := []persistence.Invitation{}
	for rows.Next() {
		var invitation persistence.Invitation
		if err := rows.Scan(&invitation.ID, &invitation.GroupID, &invitation.GroupName, &invitation.UserID, &invitation.InvitedByUserID, &invitation.InvitedByUsername); err != nil {
			return nil, err
		}
		invitations = append(invitations, invitation)
	}
	return invitations, rows.Err()
}

func (m mariadbPersistence) GetInvitation(ctx context.Context, invitationID int64) (persistence.Invitation, error) {
	row := m.db.QueryRowContext(ctx, `
		SELECT groupInvitations.id, groupInvitations.groupId, groups.name, groupInvitations.userId, groupInvitations.invitedBy, inviter.username
		FROM groupInvitations
		INNER JOIN groups ON groups.id = groupInvitations.groupId
		INNER JOIN users AS inviter ON inviter.id = groupInvitations.invitedBy
		WHERE groupInvitations.id = ?`, invitationID)
	var invitation persistence.Invitation
	if err := row.Scan(&invitation.ID, &invitation.GroupID, &invitation.GroupName, &invitation.UserID, &invitation.InvitedByUserID, &invitation.InvitedByUsername); err != nil {
		return persistence.Invitation{}, err
	}
	return invitation, nil
}

func (m mariadbPersistence) AcceptInvitation(ctx context.Context, invitationID int64, userID int64) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var groupID int64
	row := tx.QueryRowContext(ctx, `SELECT groupId FROM groupInvitations WHERE id = ? AND userId = ?`, invitationID, userID)
	if err := row.Scan(&groupID); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM groupInvitations WHERE id = ?`, invitationID); err != nil {
		return err
	}
	// INSERT IGNORE: if the user is somehow already a member (e.g. accepted
	// via a race with another invitation to the same group), keep their
	// existing role rather than erroring.
	if _, err := tx.ExecContext(ctx, `INSERT IGNORE INTO groupUsers (groupId, userId, admin, owner) VALUES (?, ?, FALSE, FALSE)`, groupID, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (m mariadbPersistence) GetUserByEmail(ctx context.Context, email string) (persistence.User, error) {
	row := m.db.QueryRowContext(ctx, `SELECT id, username, name, surname, email, passwordHash FROM users WHERE email = ?`, email)
	var user persistence.User
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Surname, &user.Email, &user.PasswordHash); err != nil {
		return persistence.User{}, err
	}
	return user, nil
}

func (m mariadbPersistence) CreatePasswordReset(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	_, err := m.db.ExecContext(ctx, `INSERT INTO passwordResets (userId, tokenHash, expiresAt) VALUES (?, ?, ?)`, userID, tokenHash, expiresAt)
	return err
}

func (m mariadbPersistence) GetPasswordResetByTokenHash(ctx context.Context, tokenHash string) (persistence.PasswordReset, error) {
	row := m.db.QueryRowContext(ctx, `SELECT id, userId, tokenHash, expiresAt, usedAt FROM passwordResets WHERE tokenHash = ?`, tokenHash)
	var reset persistence.PasswordReset
	if err := row.Scan(&reset.ID, &reset.UserID, &reset.TokenHash, &reset.ExpiresAt, &reset.UsedAt); err != nil {
		return persistence.PasswordReset{}, err
	}
	return reset, nil
}

func (m mariadbPersistence) MarkPasswordResetUsed(ctx context.Context, id int64) error {
	result, err := m.db.ExecContext(ctx, `UPDATE passwordResets SET usedAt = CURRENT_TIMESTAMP WHERE id = ? AND usedAt IS NULL`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (m mariadbPersistence) DeclineInvitation(ctx context.Context, invitationID int64, userID int64) error {
	result, err := m.db.ExecContext(ctx, `DELETE FROM groupInvitations WHERE id = ? AND userId = ?`, invitationID, userID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
