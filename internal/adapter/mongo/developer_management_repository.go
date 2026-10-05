package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	admin "iwut-auth-center/internal/administrator/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/developer/domain"
	"time"
)

const DeveloperLifecycleAuditCollection = "auth_developer_lifecycle_audit_events"

type DeveloperManagementRepository struct {
	authentication *AuthenticationRepository
	recoveryReady  bool
}

func NewDeveloperManagementRepository(a *AuthenticationRepository, ready bool) (*DeveloperManagementRepository, error) {
	if a == nil {
		return nil, d.ErrManagementUnavailable
	}
	return &DeveloperManagementRepository{a, ready}, nil
}
func EnsureDeveloperManagementSchema(ctx context.Context, db *m.Database) error {
	_, e := db.Collection(DeveloperLifecycleAuditCollection).Indexes().CreateMany(ctx, []m.IndexModel{{Keys: bson.D{{Key: "eventId", Value: 1}}, Options: options.Index().SetName("developer_lifecycle_event_unique").SetUnique(true)}, {Keys: bson.D{{Key: "subjectAuthId", Value: 1}, {Key: "occurredAt", Value: 1}, {Key: "eventId", Value: 1}}, Options: options.Index().SetName("developer_lifecycle_subject_history")}})
	return e
}
func (r *DeveloperManagementRepository) transaction(ctx context.Context, fn func(context.Context) error) error {
	var cause error
	e := r.authentication.WithAuthTransaction(ctx, func(tx context.Context) error {
		cause = nil
		e := fn(tx)
		for _, known := range d.ManagementErrors {
			if errors.Is(e, known) {
				cause = e
				break
			}
		}
		return e
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if e != nil {
		if cause != nil {
			return cause
		}
		return d.ErrManagementUnavailable
	}
	return nil
}
func (r *DeveloperManagementRepository) authorize(ctx context.Context, actor string) error {
	if e := r.authentication.ConfirmIdentityTx(ctx, actor); e != nil {
		if errors.Is(e, ap.ErrAuthenticationFailed) {
			return d.ErrManagementIdentity
		}
		return d.ErrManagementUnavailable
	}
	e := r.authentication.RequireAdministratorTx(ctx, actor)
	if errors.Is(e, admin.ErrForbidden) {
		return d.ErrManagementForbidden
	}
	if e != nil {
		return d.ErrManagementUnavailable
	}
	return nil
}
func (r *DeveloperManagementRepository) read(ctx context.Context, id string) (d.ManagedDeveloperState, error) {
	var raw bson.Raw
	e := r.authentication.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": id}).Decode(&raw)
	if errors.Is(e, m.ErrNoDocuments) {
		return d.ManagedDeveloperState{}, d.ErrManagementSubject
	}
	if e != nil {
		return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString}) {
		return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
	}
	if raw.Lookup("principalType").StringValue() == "SYSTEM" || raw.Lookup("accountStatus").StringValue() == "CLOSED" {
		return d.ManagedDeveloperState{}, d.ErrManagementSubject
	}
	if raw.Lookup("principalType").StringValue() != "USER" {
		return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"accountRevision": bson.TypeInt64, "developerRevision": bson.TypeInt64}) || raw.Lookup("accountRevision").Int64() < 1 {
		return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
	}
	rev := raw.Lookup("developerRevision").Int64()
	status := raw.Lookup("developerStatus")
	if status.Type == bson.TypeNull && rev == 0 {
		return d.ManagedDeveloperState{}, d.ErrManagementSubject
	}
	if status.Type != bson.TypeString {
		return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
	}
	state := d.ManagedDeveloperState{AuthID: id, AccountStatus: raw.Lookup("accountStatus").StringValue(), Status: status.StringValue(), Revision: rev}
	if at := raw.Lookup("developerStatusChangedAt"); at.Type != 0 {
		if at.Type != bson.TypeDateTime || at.DateTime() <= 0 {
			return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
		}
		t := time.UnixMilli(at.DateTime()).UTC()
		state.StatusChangedAt = &t
	}
	if !state.Valid() {
		return d.ManagedDeveloperState{}, d.ErrManagementUnavailable
	}
	return state, nil
}
func (r *DeveloperManagementRepository) GetManagedDeveloperStatus(ctx context.Context, actor, subject string) (d.ManagedDeveloperState, error) {
	var out d.ManagedDeveloperState
	e := r.transaction(ctx, func(tx context.Context) error {
		if e := r.authorize(tx, actor); e != nil {
			return e
		}
		var e error
		out, e = r.read(tx, subject)
		return e
	})
	if e != nil {
		return d.ManagedDeveloperState{}, e
	}
	return out, nil
}
func (r *DeveloperManagementRepository) ManageDeveloperStatus(ctx context.Context, c d.ManageDeveloperCommand) (d.ManagedDeveloperState, error) {
	var out d.ManagedDeveloperState
	eventID := uuid.NewString()
	e := r.transaction(ctx, func(tx context.Context) error {
		if e := r.authorize(tx, c.ActorAuthID); e != nil {
			return e
		}
		before, e := r.read(tx, c.SubjectAuthID)
		if e != nil {
			return e
		}
		// State/revision conflicts precede recovery eligibility; a corrupted binding
		// cannot turn an invalid state transition into a misleading email blocker.
		verified := false
		if before.Revision == c.ExpectedRevision && c.Action == "RESTORE" && before.Status == "SUSPENDED" {
			helper := DeveloperApplicationRepository{authentication: r.authentication}
			revision, e := helper.emailRevision(tx, c.SubjectAuthID)
			if e != nil {
				return d.ErrManagementUnavailable
			}
			verified = revision > 0
		}
		now := r.authentication.currentTime(time.Time{})
		after, e := d.ChangeDeveloperStatus(before, c, verified, r.recoveryReady, now)
		if e != nil {
			return e
		}
		result, e := r.authentication.database.Collection(PrincipalCollection).UpdateOne(tx, bson.M{"authId": before.AuthID, "principalType": "USER", "accountStatus": before.AccountStatus, "developerStatus": before.Status, "developerRevision": before.Revision}, bson.M{"$set": bson.M{"developerStatus": after.Status, "developerRevision": after.Revision, "developerStatusChangedAt": now, "developerStatusChangedBy": bson.M{"actorType": "USER", "actorAuthId": c.ActorAuthID}}, "$inc": bson.M{"authenticationFence": int64(1)}})
		if e != nil {
			return e
		}
		if result.MatchedCount != 1 {
			return d.ErrManagementConflict
		}
		if e = r.authentication.CancelPendingOwnerExitsTx(tx, before.AuthID, "DEVELOPER_STATUS_CHANGED", now); e != nil {
			return e
		}
		_, e = r.authentication.database.Collection(DeveloperLifecycleAuditCollection).InsertOne(tx, bson.M{"eventId": eventID, "actorType": "USER", "actorAuthId": c.ActorAuthID, "subjectAuthId": before.AuthID, "action": c.Action, "reason": c.Reason, "beforeStatus": before.Status, "afterStatus": after.Status, "beforeRevision": before.Revision, "afterRevision": after.Revision, "occurredAt": now})
		if e != nil {
			return e
		}
		out = after
		return nil
	})
	if e != nil {
		return d.ManagedDeveloperState{}, e
	}
	return out, nil
}
