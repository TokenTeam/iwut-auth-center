package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/account/domain"
	admin "iwut-auth-center/internal/administrator/domain"
	ap "iwut-auth-center/internal/authentication/port"
	"math"
	"time"
)

const AccountStatusAuditCollection = "auth_account_status_audit_events"

type AccountAdministration interface {
	RequireAdministratorTx(context.Context, string) error
	EnsureAnotherAdministratorTx(context.Context, string) error
}
type AccountManagementRepository struct {
	auth   *AuthenticationRepository
	admins AccountAdministration
}

func NewAccountManagementRepository(a *AuthenticationRepository) (*AccountManagementRepository, error) {
	if a == nil {
		return nil, d.ErrUnavailable
	}
	return &AccountManagementRepository{a, a}, nil
}
func EnsureAccountManagementSchema(ctx context.Context, db *m.Database) error {
	_, err := db.Collection(AccountStatusAuditCollection).Indexes().CreateMany(ctx, []m.IndexModel{{Keys: bson.D{{Key: "eventId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("account_status_event_unique")}, {Keys: bson.D{{Key: "subjectAuthId", Value: 1}, {Key: "occurredAt", Value: 1}, {Key: "eventId", Value: 1}}, Options: options.Index().SetName("account_status_subject_history")}})
	return err
}
func (r *AccountManagementRepository) transaction(ctx context.Context, fn func(context.Context) error) error {
	var semantic error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error { semantic = fn(tx); return semantic })
	if err == nil {
		return nil
	}
	for _, known := range []error{d.ErrIdentity, d.ErrForbidden, d.ErrSubject, d.ErrConflict, d.ErrLastAdmin, d.ErrExhausted} {
		if errors.Is(semantic, known) {
			return known
		}
	}
	return d.ErrUnavailable
}
func (r *AccountManagementRepository) authorize(tx context.Context, actor string) error {
	if err := r.auth.ConfirmIdentityTx(tx, actor); err != nil {
		if errors.Is(err, ap.ErrAuthenticationFailed) {
			return d.ErrIdentity
		}
		return err
	}
	if err := r.admins.RequireAdministratorTx(tx, actor); err != nil {
		if errors.Is(err, admin.ErrForbidden) {
			return d.ErrForbidden
		}
		return err
	}
	return nil
}
func (r *AccountManagementRepository) read(tx context.Context, id string) (d.State, error) {
	var raw bson.Raw
	err := r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": id}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return d.State{}, d.ErrSubject
	}
	if err != nil {
		return d.State{}, err
	}
	if v := raw.Lookup("principalType"); v.Type == bson.TypeString && v.StringValue() == "SYSTEM" {
		return d.State{}, d.ErrSubject
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString, "accountRevision": bson.TypeInt64}) {
		return d.State{}, d.ErrUnavailable
	}
	if raw.Lookup("principalType").StringValue() != "USER" {
		return d.State{}, d.ErrSubject
	}
	s := d.State{AuthID: id, Status: raw.Lookup("accountStatus").StringValue(), Revision: raw.Lookup("accountRevision").Int64()}
	if s.Status == "CLOSED" {
		return s, d.ErrSubject
	}
	if s.Revision <= 0 || (s.Status != "ACTIVE" && s.Status != "DISABLED") {
		return s, d.ErrUnavailable
	}
	if v := raw.Lookup("statusChangedAt"); v.Type != 0 && v.Type != bson.TypeNull {
		if v.Type != bson.TypeDateTime {
			return s, d.ErrUnavailable
		}
		at := v.Time()
		s.ChangedAt = &at
	}
	return s, nil
}
func (r *AccountManagementRepository) Get(ctx context.Context, actor, subject string) (d.State, error) {
	var result d.State
	err := r.transaction(ctx, func(tx context.Context) error {
		if err := r.authorize(tx, actor); err != nil {
			return err
		}
		var err error
		result, err = r.read(tx, subject)
		return err
	})
	if err != nil {
		return d.State{}, err
	}
	return result, nil
}
func (r *AccountManagementRepository) Manage(ctx context.Context, c d.Command) (d.State, error) {
	var result d.State
	eventID := uuid.NewString()
	err := r.transaction(ctx, func(tx context.Context) error {
		if err := r.authorize(tx, c.ActorAuthID); err != nil {
			return err
		}
		before, err := r.read(tx, c.SubjectAuthID)
		if err != nil {
			return err
		}
		if before.Revision != c.ExpectedRevision {
			return d.ErrConflict
		}
		want := "DISABLED"
		if c.Action == "RESTORE" {
			want = "ACTIVE"
		}
		if before.Status == want {
			return d.ErrConflict
		}
		if before.Revision == math.MaxInt64 {
			return d.ErrExhausted
		}
		if c.Action == "DISABLE" {
			if err := r.admins.EnsureAnotherAdministratorTx(tx, c.SubjectAuthID); err != nil {
				if errors.Is(err, admin.ErrLast) {
					return d.ErrLastAdmin
				}
				return err
			}
		}
		now := r.auth.currentTime(time.Time{})
		result = d.State{AuthID: before.AuthID, Status: want, Revision: before.Revision + 1, ChangedAt: &now}
		updated, err := r.auth.database.Collection(PrincipalCollection).UpdateOne(tx, bson.M{"authId": before.AuthID, "accountStatus": before.Status, "accountRevision": before.Revision}, bson.M{"$set": bson.M{"accountStatus": want, "accountRevision": result.Revision, "statusChangedAt": now, "accountStatusUpdatedBy": c.ActorAuthID}})
		if err != nil {
			return err
		}
		if updated.MatchedCount != 1 {
			return d.ErrConflict
		}
		if c.Action == "DISABLE" {
			if err = r.auth.CancelPendingOwnerExitsTx(tx, c.SubjectAuthID, "ACCOUNT_DISABLED", now); err != nil {
				return err
			}
		}
		_, err = r.auth.database.Collection(AccountStatusAuditCollection).InsertOne(tx, bson.M{"eventId": eventID, "actorAuthId": c.ActorAuthID, "subjectAuthId": c.SubjectAuthID, "action": c.Action, "reason": c.Reason, "beforeStatus": before.Status, "afterStatus": want, "beforeAccountRevision": before.Revision, "afterAccountRevision": result.Revision, "occurredAt": now})
		return err
	})
	if err != nil {
		return d.State{}, err
	}
	return result, nil
}
