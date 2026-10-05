package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/administrator/domain"
	ap "iwut-auth-center/internal/authentication/port"
	"time"
)

const PlatformAdminAuditCollection = "auth_platform_admin_audit_events"

type PlatformAdministratorRepository struct {
	authentication *AuthenticationRepository
	recoveryReady  bool
}

func NewPlatformAdministratorRepository(a *AuthenticationRepository, ready bool) (*PlatformAdministratorRepository, error) {
	if a == nil {
		return nil, d.ErrUnavailable
	}
	return &PlatformAdministratorRepository{a, ready}, nil
}
func EnsurePlatformAdministratorSchema(ctx context.Context, db *m.Database) error {
	_, err := db.Collection(PlatformAdminAuditCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "eventId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("platform_admin_event_unique")},
		{Keys: bson.D{{Key: "subjectAuthId", Value: 1}, {Key: "occurredAt", Value: 1}, {Key: "eventId", Value: 1}}, Options: options.Index().SetName("platform_admin_subject_history")},
	})
	return err
}
func (r *PlatformAdministratorRepository) transaction(ctx context.Context, fn func(context.Context) error) error {
	var cause error
	err := r.authentication.WithAuthTransaction(ctx, func(tx context.Context) error {
		cause = nil
		err := fn(tx)
		for _, known := range d.Errors {
			if errors.Is(err, known) {
				cause = err
				break
			}
		}
		return err
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if cause != nil {
			return cause
		}
		return d.ErrUnavailable
	}
	return nil
}
func (a *AuthenticationRepository) administratorMarkerTx(ctx context.Context) (bson.Raw, error) {
	var raw bson.Raw
	if err := a.database.Collection(AuthenticationRuntimeCollection).FindOne(ctx, bson.M{"_id": bootstrapMarker}).Decode(&raw); err != nil {
		return nil, d.ErrUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"subjectAuthId": bson.TypeString, "eventId": bson.TypeString, "occurredAt": bson.TypeDateTime, "bundleVersion": bson.TypeInt32}) || !d.ValidID(raw.Lookup("subjectAuthId").StringValue()) || raw.Lookup("eventId").StringValue() == "" || raw.Lookup("occurredAt").DateTime() <= 0 || raw.Lookup("bundleVersion").Int32() != 1 {
		return nil, d.ErrUnavailable
	}
	var audit bson.Raw
	if err := a.database.Collection(PlatformAdminAuditCollection).FindOne(ctx, bson.M{"eventId": raw.Lookup("eventId").StringValue(), "subjectAuthId": raw.Lookup("subjectAuthId").StringValue(), "actorType": "BOOTSTRAP_COMMAND", "operation": "GRANT", "bundleVersion": int32(1), "occurredAt": time.UnixMilli(raw.Lookup("occurredAt").DateTime())}).Decode(&audit); err != nil {
		return nil, d.ErrUnavailable
	}
	if !identityFields(audit, map[string]bson.Type{"beforePermissionRevision": bson.TypeInt64, "afterPermissionRevision": bson.TypeInt64, "beforePermissions": bson.TypeArray, "afterPermissions": bson.TypeArray}) || audit.Lookup("actorAuthId").Type != 0 {
		return nil, d.ErrUnavailable
	}
	before, after := audit.Lookup("beforePermissionRevision").Int64(), audit.Lookup("afterPermissionRevision").Int64()
	if before <= 0 || after <= before || after-before != 1 {
		return nil, d.ErrUnavailable
	}
	bv, e := adminPermissions(audit.Lookup("beforePermissions"))
	if e != nil || len(bv) != 0 {
		return nil, d.ErrUnavailable
	}
	av, e := adminPermissions(audit.Lookup("afterPermissions"))
	if e != nil || len(av) != 4 {
		return nil, d.ErrUnavailable
	}
	g, e := d.Membership(av)
	if e != nil || !g {
		return nil, d.ErrUnavailable
	}
	return raw, nil
}
func adminPermissions(v bson.RawValue) ([]string, error) {
	if v.Type != bson.TypeArray {
		return nil, d.ErrUnavailable
	}
	values, e := v.Array().Values()
	if e != nil {
		return nil, d.ErrUnavailable
	}
	out := []string{}
	for _, x := range values {
		if x.Type != bson.TypeString {
			return nil, d.ErrUnavailable
		}
		out = append(out, x.StringValue())
	}
	return out, nil
}
func (a *AuthenticationRepository) administratorSnapshotTx(ctx context.Context, id string) (d.Snapshot, error) {
	var raw bson.Raw
	err := a.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": id}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return d.Snapshot{}, d.ErrSubject
	}
	if err != nil {
		return d.Snapshot{}, d.ErrUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString}) {
		return d.Snapshot{}, d.ErrUnavailable
	}
	if raw.Lookup("principalType").StringValue() == "SYSTEM" {
		return d.Snapshot{}, d.ErrSubject
	}
	if raw.Lookup("principalType").StringValue() != "USER" {
		return d.Snapshot{}, d.ErrUnavailable
	}
	if raw.Lookup("accountStatus").StringValue() == "CLOSED" {
		return d.Snapshot{}, d.ErrSubject
	}
	if !identityFields(raw, map[string]bson.Type{"accountRevision": bson.TypeInt64, "permissionRevision": bson.TypeInt64, "permissions": bson.TypeArray}) || raw.Lookup("accountRevision").Int64() <= 0 {
		return d.Snapshot{}, d.ErrUnavailable
	}
	p, err := adminPermissions(raw.Lookup("permissions"))
	if err != nil {
		return d.Snapshot{}, err
	}
	s := d.Snapshot{AuthID: id, AccountStatus: raw.Lookup("accountStatus").StringValue(), Permissions: p, Revision: raw.Lookup("permissionRevision").Int64()}
	_, err = s.State()
	return s, err
}

// RequireAdministratorTx is used only within WithAuthTransaction. All governance
// reads and writes verify the durable initialization and current complete bundle.
func (a *AuthenticationRepository) RequireAdministratorTx(ctx context.Context, id string) error {
	if err := a.ConfirmIdentityTx(ctx, id); err != nil {
		if errors.Is(err, ap.ErrAuthenticationFailed) {
			return d.ErrForbidden
		}
		return d.ErrUnavailable
	}
	if _, err := a.administratorMarkerTx(ctx); err != nil {
		return err
	}
	s, err := a.administratorSnapshotTx(ctx, id)
	if errors.Is(err, d.ErrSubject) {
		return d.ErrForbidden
	}
	if err != nil {
		return err
	}
	state, err := s.State()
	if err != nil {
		return err
	}
	if !state.Effective() {
		return d.ErrForbidden
	}
	result, err := a.database.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": id, "principalType": "USER", "accountStatus": "ACTIVE", "permissionRevision": s.Revision, "permissions": bson.M{"$all": d.Permissions()}}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}})
	if err != nil {
		return d.ErrUnavailable
	}
	if result.MatchedCount != 1 {
		return d.ErrForbidden
	}
	return nil
}

// EnsureAnotherAdministratorTx shares the global authentication write fence with
// grant/revoke, disable and closure; a snapshot-only count would allow write skew.
func (a *AuthenticationRepository) EnsureAnotherAdministratorTx(ctx context.Context, excluded string) error {
	cursor, err := a.database.Collection(PrincipalCollection).Find(ctx, bson.M{"authId": bson.M{"$ne": excluded}, "permissions": bson.M{"$in": d.Permissions()}})
	if err != nil {
		return d.ErrUnavailable
	}
	defer cursor.Close(ctx)
	found := false
	for cursor.Next(ctx) {
		var raw bson.Raw
		if cursor.Decode(&raw) != nil || raw.Lookup("authId").Type != bson.TypeString {
			return d.ErrUnavailable
		}
		s, e := a.administratorSnapshotTx(ctx, raw.Lookup("authId").StringValue())
		if e != nil {
			return d.ErrUnavailable
		}
		state, e := s.State()
		if e != nil {
			return e
		}
		if state.Effective() {
			found = true
		}
	}
	if cursor.Err() != nil {
		return d.ErrUnavailable
	}
	if !found {
		return d.ErrLast
	}
	return nil
}
func (r *PlatformAdministratorRepository) snapshot(ctx context.Context, id string) (d.Snapshot, error) {
	s, e := r.authentication.administratorSnapshotTx(ctx, id)
	if e != nil {
		return s, e
	}
	helper := DeveloperApplicationRepository{authentication: r.authentication}
	rev, e := helper.emailRevision(ctx, id)
	if e != nil {
		return d.Snapshot{}, d.ErrUnavailable
	}
	s.EmailVerified = rev > 0
	s.RecoveryReady = r.recoveryReady
	return s, nil
}
func (r *PlatformAdministratorRepository) Get(ctx context.Context, actor, subject string) (d.State, error) {
	var out d.State
	e := r.transaction(ctx, func(tx context.Context) error {
		if e := r.authentication.RequireAdministratorTx(tx, actor); e != nil {
			return e
		}
		s, e := r.snapshot(tx, subject)
		if e != nil {
			return e
		}
		out, e = s.State()
		return e
	})
	if e != nil {
		return d.State{}, e
	}
	return out, nil
}
func (r *PlatformAdministratorRepository) List(ctx context.Context, actor, after string, size int) (d.Page, error) {
	var out d.Page
	e := r.transaction(ctx, func(tx context.Context) error {
		if e := r.authentication.RequireAdministratorTx(tx, actor); e != nil {
			return e
		}
		out = d.Page{Items: []d.State{}, ObservedAt: r.authentication.currentTime(time.Time{})}
		cursor, e := r.authentication.database.Collection(PrincipalCollection).Find(tx, bson.M{"authId": bson.M{"$gt": after}, "permissions": bson.M{"$in": d.Permissions()}}, options.Find().SetSort(bson.D{{Key: "authId", Value: 1}}).SetCollation(&options.Collation{Locale: "simple"}).SetLimit(int64(size+1)))
		if e != nil {
			return e
		}
		defer cursor.Close(tx)
		for cursor.Next(tx) {
			var raw bson.Raw
			if cursor.Decode(&raw) != nil || raw.Lookup("authId").Type != bson.TypeString {
				return d.ErrUnavailable
			}
			s, e := r.snapshot(tx, raw.Lookup("authId").StringValue())
			if e != nil {
				return d.ErrUnavailable
			}
			state, e := s.State()
			if e != nil || !state.Granted {
				return d.ErrUnavailable
			}
			if len(out.Items) == size {
				out.NextAfterAuthID = out.Items[size-1].AuthID
				break
			}
			out.Items = append(out.Items, state)
		}
		return cursor.Err()
	})
	if e != nil {
		return d.Page{}, e
	}
	return out, nil
}
func (r *PlatformAdministratorRepository) Manage(ctx context.Context, c d.Command) (d.State, error) {
	var out d.State
	eventID := uuid.NewString()
	e := r.transaction(ctx, func(tx context.Context) error {
		if e := r.authentication.RequireAdministratorTx(tx, c.ActorAuthID); e != nil {
			return e
		}
		before, e := r.snapshot(tx, c.SubjectAuthID)
		if e != nil {
			return e
		}
		after, e := d.Change(before, c)
		if e != nil {
			return e
		}
		if c.Action == "REVOKE" {
			if e = r.authentication.EnsureAnotherAdministratorTx(tx, c.SubjectAuthID); e != nil {
				return e
			}
		}
		if e = r.write(tx, before, after, c.Action, c.Reason, "USER", c.ActorAuthID, eventID, r.authentication.currentTime(time.Time{})); e != nil {
			return e
		}
		out, e = after.State()
		return e
	})
	if e != nil {
		return d.State{}, e
	}
	return out, nil
}
func (r *PlatformAdministratorRepository) write(ctx context.Context, before, after d.Snapshot, operation, reason, actorType, actor, eventID string, now time.Time) error {
	attribution := bson.M{"actorType": actorType}
	if actor != "" {
		attribution["actorAuthId"] = actor
	}
	result, e := r.authentication.database.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": before.AuthID, "principalType": "USER", "accountStatus": before.AccountStatus, "permissionRevision": before.Revision}, bson.M{"$set": bson.M{"permissions": after.Permissions, "permissionRevision": after.Revision, "permissionUpdatedAt": now, "permissionUpdatedBy": attribution}, "$inc": bson.M{"authenticationFence": int64(1)}})
	if e != nil {
		return e
	}
	if result.MatchedCount != 1 {
		return d.ErrConflict
	}
	subset := func(s d.Snapshot) []string {
		g, _ := d.Membership(s.Permissions)
		if g {
			return d.Permissions()
		}
		return []string{}
	}
	audit := bson.M{"eventId": eventID, "operation": operation, "actorType": actorType, "subjectAuthId": before.AuthID, "reason": reason, "bundleVersion": int32(1), "beforePermissions": subset(before), "afterPermissions": subset(after), "beforePermissionRevision": before.Revision, "afterPermissionRevision": after.Revision, "occurredAt": now}
	if actor != "" {
		audit["actorAuthId"] = actor
	}
	_, e = r.authentication.database.Collection(PlatformAdminAuditCollection).InsertOne(ctx, audit)
	return e
}
func (r *PlatformAdministratorRepository) Bootstrap(ctx context.Context, id string) (d.BootstrapResult, error) {
	var out d.BootstrapResult
	eventID := uuid.NewString()
	e := r.transaction(ctx, func(tx context.Context) error {
		out = d.BootstrapResult{}
		a := r.authentication
		var marker bson.Raw
		e := a.database.Collection(AuthenticationRuntimeCollection).FindOne(tx, bson.M{"_id": bootstrapMarker}).Decode(&marker)
		if e == nil {
			raw, e := a.administratorMarkerTx(tx)
			if e != nil {
				return e
			}
			if raw.Lookup("subjectAuthId").StringValue() != id {
				return d.ErrBootstrapConsumed
			}
			out.EventID = raw.Lookup("eventId").StringValue()
			return nil
		}
		if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		count, e := a.database.Collection(PrincipalCollection).CountDocuments(tx, bson.M{"permissions": bson.M{"$in": d.Permissions()}})
		if e != nil {
			return e
		}
		if count != 0 {
			return d.ErrUnavailable
		}
		before, e := r.snapshot(tx, id)
		if e != nil {
			return e
		}
		after, e := d.Change(before, d.Command{Action: "GRANT", ExpectedRevision: before.Revision})
		if e != nil {
			return e
		}
		now := a.currentTime(time.Time{})
		if e = r.write(tx, before, after, "GRANT", "one-time platform administrator bootstrap", "BOOTSTRAP_COMMAND", "", eventID, now); e != nil {
			return e
		}
		_, e = a.database.Collection(AuthenticationRuntimeCollection).InsertOne(tx, bson.M{"_id": bootstrapMarker, "subjectAuthId": id, "eventId": eventID, "occurredAt": now, "bundleVersion": int32(1)})
		if e != nil {
			return e
		}
		out = d.BootstrapResult{Applied: true, EventID: eventID}
		return nil
	})
	if e != nil {
		return d.BootstrapResult{}, e
	}
	return out, nil
}
