package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/reviewer/domain"
	"time"
)

const PermissionAuditCollection = "auth_permission_audit_events"
const bootstrapMarker = "platform-admin-bootstrap"

type ReviewerRepository struct{ authentication *AuthenticationRepository }

func NewReviewerRepository(a *AuthenticationRepository) (*ReviewerRepository, error) {
	if a == nil {
		return nil, domain.ErrUnavailable
	}
	return &ReviewerRepository{a}, nil
}
func EnsureReviewerSchema(ctx context.Context, db *drivermongo.Database) error {
	_, err := db.Collection(PermissionAuditCollection).Indexes().CreateMany(ctx, []drivermongo.IndexModel{
		{Keys: bson.D{{Key: "eventId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("permission_event_unique")},
		{Keys: bson.D{{Key: "subjectAuthId", Value: 1}, {Key: "afterRevision", Value: 1}}, Options: options.Index().SetUnique(true).SetName("permission_subject_revision_unique")},
	})
	return err
}
func (r *ReviewerRepository) transaction(ctx context.Context, fn func(context.Context) error) error {
	var applicationErr error
	err := r.authentication.WithAuthTransaction(ctx, func(tx context.Context) error {
		applicationErr = nil
		err := fn(tx)
		for _, known := range []error{domain.ErrForbidden, domain.ErrSubject, domain.ErrConflict, domain.ErrExhausted, domain.ErrBootstrapConsumed, domain.ErrUnavailable} {
			if errors.Is(err, known) {
				applicationErr = known
				break
			}
		}
		return err
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if applicationErr != nil {
			return applicationErr
		}
		return domain.ErrUnavailable
	}
	return nil
}
func (r *ReviewerRepository) read(ctx context.Context, id string) (domain.State, error) {
	var raw bson.Raw
	err := r.authentication.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": id}).Decode(&raw)
	if errors.Is(err, drivermongo.ErrNoDocuments) {
		return domain.State{}, domain.ErrSubject
	}
	if err != nil {
		return domain.State{}, err
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString}) {
		return domain.State{}, domain.ErrUnavailable
	}
	if raw.Lookup("principalType").StringValue() != "USER" || raw.Lookup("accountStatus").StringValue() != "ACTIVE" {
		return domain.State{}, domain.ErrSubject
	}
	if !identityFields(raw, map[string]bson.Type{"permissions": bson.TypeArray, "permissionRevision": bson.TypeInt64}) {
		return domain.State{}, domain.ErrUnavailable
	}
	s := domain.State{AuthID: id, Revision: raw.Lookup("permissionRevision").Int64(), Permissions: []string{}}
	values, err := raw.Lookup("permissions").Array().Values()
	if err != nil {
		return domain.State{}, domain.ErrUnavailable
	}
	for _, v := range values {
		if v.Type != bson.TypeString {
			return domain.State{}, domain.ErrUnavailable
		}
		s.Permissions = append(s.Permissions, v.StringValue())
	}
	if !s.Valid() {
		return domain.State{}, domain.ErrUnavailable
	}
	return s, nil
}
func (r *ReviewerRepository) authorize(ctx context.Context, actor string) error {
	s, err := r.read(ctx, actor)
	if errors.Is(err, domain.ErrSubject) {
		return domain.ErrForbidden
	}
	if err != nil {
		return err
	}
	if !s.Has(domain.Manager) {
		return domain.ErrForbidden
	}
	result, err := r.authentication.database.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": actor, "principalType": "USER", "accountStatus": "ACTIVE", "permissionRevision": s.Revision, "permissions": domain.Manager}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}})
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return domain.ErrForbidden
	}
	return nil
}
func (r *ReviewerRepository) Get(ctx context.Context, actor, subject string) (domain.State, error) {
	var state domain.State
	err := r.transaction(ctx, func(tx context.Context) error {
		if err := r.authorize(tx, actor); err != nil {
			return err
		}
		var err error
		state, err = r.read(tx, subject)
		return err
	})
	if err != nil {
		return domain.State{}, err
	}
	return state, nil
}
func (r *ReviewerRepository) Manage(ctx context.Context, c domain.Command) (domain.State, error) {
	var result domain.State
	err := r.transaction(ctx, func(tx context.Context) error {
		if err := r.authorize(tx, c.ActorAuthID); err != nil {
			return err
		}
		before, err := r.read(tx, c.SubjectAuthID)
		if err != nil {
			return err
		}
		next, err := domain.Change(before, c.Permission, c.Action, c.ExpectedRevision)
		if err != nil {
			return err
		}
		if err = r.write(tx, before, next, c.Permission, c.Action, c.Reason, "USER", c.ActorAuthID, uuid.NewString()); err != nil {
			return err
		}
		result = next
		return nil
	})
	if err != nil {
		return domain.State{}, err
	}
	return result, nil
}
func (r *ReviewerRepository) write(ctx context.Context, before, after domain.State, permission, action, reason, actorType, actor, eventID string) error {
	now := r.authentication.currentTime(time.Time{})
	attribution := bson.M{"actorType": actorType}
	if actor != "" {
		attribution["actorAuthId"] = actor
	}
	result, err := r.authentication.database.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": before.AuthID, "principalType": "USER", "accountStatus": "ACTIVE", "permissionRevision": before.Revision}, bson.M{"$set": bson.M{"permissions": after.Permissions, "permissionRevision": after.Revision, "permissionUpdatedBy": attribution, "permissionUpdatedAt": now}, "$inc": bson.M{"authenticationFence": int64(1)}})
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return domain.ErrConflict
	}
	event := bson.M{"eventId": eventID, "subjectAuthId": before.AuthID, "actorType": actorType, "action": action, "permission": permission, "reason": reason, "beforeRevision": before.Revision, "afterRevision": after.Revision, "beforePermissions": before.Permissions, "afterPermissions": after.Permissions, "occurredAt": now}
	if actor != "" {
		event["actorAuthId"] = actor
	}
	_, err = r.authentication.database.Collection(PermissionAuditCollection).InsertOne(ctx, event)
	return err
}
func (r *ReviewerRepository) Bootstrap(ctx context.Context, id string) (bool, error) {
	applied := false
	err := r.transaction(ctx, func(tx context.Context) error {
		applied = false
		var marker bson.Raw
		err := r.authentication.database.Collection(AuthenticationRuntimeCollection).FindOne(tx, bson.M{"_id": bootstrapMarker}).Decode(&marker)
		if err == nil {
			if !identityFields(marker, map[string]bson.Type{"subjectAuthId": bson.TypeString, "eventId": bson.TypeString, "occurredAt": bson.TypeDateTime}) {
				return domain.ErrUnavailable
			}
			if marker.Lookup("subjectAuthId").StringValue() != id {
				return domain.ErrBootstrapConsumed
			}
			return nil
		}
		if !errors.Is(err, drivermongo.ErrNoDocuments) {
			return err
		}
		before, err := r.read(tx, id)
		if err != nil {
			return err
		}
		next, err := domain.Change(before, domain.Manager, "GRANT", before.Revision)
		if err != nil {
			return err
		}
		eventID := uuid.NewString()
		if err = r.write(tx, before, next, domain.Manager, "GRANT", "one-time platform administrator bootstrap", "BOOTSTRAP_COMMAND", "", eventID); err != nil {
			return err
		}
		_, err = r.authentication.database.Collection(AuthenticationRuntimeCollection).InsertOne(tx, bson.M{"_id": bootstrapMarker, "subjectAuthId": id, "eventId": eventID, "occurredAt": r.authentication.currentTime(time.Time{})})
		if err != nil {
			return err
		}
		applied = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return applied, nil
}
