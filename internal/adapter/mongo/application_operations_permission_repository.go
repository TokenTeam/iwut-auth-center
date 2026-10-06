package mongo

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"

	admin "iwut-auth-center/internal/administrator/domain"
	domain "iwut-auth-center/internal/applicationoperations/domain"
)

type ApplicationOperationsPermissionRepository struct {
	authentication *AuthenticationRepository
	recoveryReady  bool
}

func NewApplicationOperationsPermissionRepository(authentication *AuthenticationRepository, recoveryReady bool) (*ApplicationOperationsPermissionRepository, error) {
	if authentication == nil {
		return nil, domain.ErrUnavailable
	}
	return &ApplicationOperationsPermissionRepository{authentication: authentication, recoveryReady: recoveryReady}, nil
}

func (r *ApplicationOperationsPermissionRepository) transaction(ctx context.Context, operation func(context.Context) error) error {
	var semantic error
	err := r.authentication.WithAuthTransaction(ctx, func(tx context.Context) error {
		semantic = operation(tx)
		return semantic
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	for _, known := range []error{domain.ErrIdentity, domain.ErrForbidden, domain.ErrSubject, domain.ErrConflict, domain.ErrGrantBlocked, domain.ErrExhausted, domain.ErrUnavailable} {
		if errors.Is(semantic, known) {
			return semantic
		}
	}
	return domain.ErrUnavailable
}

func (r *ApplicationOperationsPermissionRepository) authorize(ctx context.Context, actor string) error {
	err := r.authentication.RequireAdministratorTx(ctx, actor)
	if errors.Is(err, admin.ErrIdentity) {
		return domain.ErrIdentity
	}
	if errors.Is(err, admin.ErrForbidden) {
		return domain.ErrForbidden
	}
	if err != nil {
		return domain.ErrUnavailable
	}
	return nil
}

func (r *ApplicationOperationsPermissionRepository) snapshot(ctx context.Context, id string) (domain.Snapshot, error) {
	var raw bson.Raw
	err := r.authentication.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": id}).Decode(&raw)
	if errors.Is(err, drivermongo.ErrNoDocuments) {
		return domain.Snapshot{}, domain.ErrSubject
	}
	if err != nil {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString, "permissions": bson.TypeArray, "permissionRevision": bson.TypeInt64}) {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	if raw.Lookup("principalType").StringValue() != "USER" {
		if raw.Lookup("principalType").StringValue() == "SYSTEM" {
			return domain.Snapshot{}, domain.ErrSubject
		}
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	status := raw.Lookup("accountStatus").StringValue()
	if status == "CLOSED" {
		return domain.Snapshot{}, domain.ErrSubject
	}
	if status != "ACTIVE" && status != "DISABLED" {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	permissions, err := adminPermissions(raw.Lookup("permissions"))
	if err != nil {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	if _, err = admin.Membership(permissions); err != nil {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	emailRevision, err := (&DeveloperApplicationRepository{authentication: r.authentication}).emailRevision(ctx, id)
	if err != nil {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	snapshot := domain.Snapshot{AuthID: id, AccountStatus: status, Permissions: permissions, Revision: raw.Lookup("permissionRevision").Int64(), EmailVerified: emailRevision > 0, RecoveryReady: r.recoveryReady}
	if _, err = snapshot.State(); err != nil {
		return domain.Snapshot{}, err
	}
	return snapshot, nil
}

func (r *ApplicationOperationsPermissionRepository) Get(ctx context.Context, actor, subject string) (domain.State, error) {
	var state domain.State
	err := r.transaction(ctx, func(tx context.Context) error {
		if err := r.authorize(tx, actor); err != nil {
			return err
		}
		snapshot, err := r.snapshot(tx, subject)
		if err != nil {
			return err
		}
		state, err = snapshot.State()
		return err
	})
	if err != nil {
		return domain.State{}, err
	}
	return state, nil
}

func (r *ApplicationOperationsPermissionRepository) Manage(ctx context.Context, command domain.Command) (domain.State, error) {
	var state domain.State
	eventID := uuid.NewString()
	err := r.transaction(ctx, func(tx context.Context) error {
		if err := r.authorize(tx, command.ActorAuthID); err != nil {
			return err
		}
		before, err := r.snapshot(tx, command.SubjectAuthID)
		if err != nil {
			return err
		}
		after, err := domain.Change(before, command)
		if err != nil {
			return err
		}
		if err = r.write(tx, before, after, command, eventID); err != nil {
			return err
		}
		state, err = after.State()
		return err
	})
	if err != nil {
		return domain.State{}, err
	}
	return state, nil
}

func (r *ApplicationOperationsPermissionRepository) write(ctx context.Context, before, after domain.Snapshot, command domain.Command, eventID string) error {
	now := r.authentication.currentTime(time.Time{})
	attribution := bson.M{"actorType": "USER", "actorAuthId": command.ActorAuthID}
	result, err := r.authentication.database.Collection(PrincipalCollection).UpdateOne(ctx,
		bson.M{"authId": before.AuthID, "principalType": "USER", "accountStatus": before.AccountStatus, "permissionRevision": before.Revision},
		bson.M{"$set": bson.M{"permissions": after.Permissions, "permissionRevision": after.Revision, "permissionUpdatedBy": attribution, "permissionUpdatedAt": now}, "$inc": bson.M{"authenticationFence": int64(1)}},
	)
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return domain.ErrConflict
	}
	_, err = r.authentication.database.Collection(PermissionAuditCollection).InsertOne(ctx, bson.M{
		"eventId": eventID, "subjectAuthId": before.AuthID, "actorType": "USER", "actorAuthId": command.ActorAuthID,
		"action": command.Action, "permission": command.Permission, "reason": command.Reason,
		"beforeRevision": before.Revision, "afterRevision": after.Revision,
		"beforePermissions": before.Permissions, "afterPermissions": after.Permissions, "occurredAt": now,
	})
	return err
}
