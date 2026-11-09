package mongo

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"

	admin "iwut-auth-center/internal/administrator/domain"
	"iwut-auth-center/internal/scriptmaintainer/domain"
)

type ScriptMaintainerPermissionRepository struct {
	auth          *AuthenticationRepository
	recoveryReady bool
}

func NewScriptMaintainerPermissionRepository(auth *AuthenticationRepository, recoveryReady bool) *ScriptMaintainerPermissionRepository {
	return &ScriptMaintainerPermissionRepository{auth: auth, recoveryReady: recoveryReady}
}

func (r *ScriptMaintainerPermissionRepository) transaction(ctx context.Context, actor string, run func(context.Context) error) error {
	var semantic error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		semantic = nil
		switch e := r.auth.RequireAdministratorTx(tx, actor); {
		case errors.Is(e, admin.ErrIdentity):
			semantic = domain.ErrIdentity
		case errors.Is(e, admin.ErrForbidden):
			semantic = domain.ErrForbidden
		case e != nil:
			return e
		default:
			semantic = run(tx)
		}
		return semantic
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	for _, known := range []error{domain.ErrIdentity, domain.ErrInvalid, domain.ErrForbidden, domain.ErrSubject, domain.ErrConflict, domain.ErrGrantBlocked, domain.ErrExhausted, domain.ErrUnavailable} {
		if errors.Is(semantic, known) {
			return known
		}
	}
	return domain.ErrUnavailable
}

func (r *ScriptMaintainerPermissionRepository) snapshot(ctx context.Context, subject string) (domain.Snapshot, error) {
	var raw bson.Raw
	err := r.auth.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": subject}).Decode(&raw)
	if errors.Is(err, drivermongo.ErrNoDocuments) {
		return domain.Snapshot{}, domain.ErrSubject
	}
	if err != nil {
		return domain.Snapshot{}, err
	}
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString}) || raw.Lookup("authId").StringValue() != subject {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	switch raw.Lookup("principalType").StringValue() {
	case "SYSTEM":
		return domain.Snapshot{}, domain.ErrSubject
	case "USER":
	default:
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	status, ok := raw.Lookup("accountStatus").StringValueOK()
	if ok && status == "CLOSED" && validClosedPrincipal(raw) {
		return domain.Snapshot{}, domain.ErrSubject
	}
	if !ok || !identityFields(raw, map[string]bson.Type{"accountRevision": bson.TypeInt64, "permissionRevision": bson.TypeInt64, "permissions": bson.TypeArray}) || raw.Lookup("accountRevision").Int64() <= 0 {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	permissions, err := adminPermissions(raw.Lookup("permissions"))
	if err != nil {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	if _, err = admin.Membership(permissions); err != nil {
		return domain.Snapshot{}, domain.ErrUnavailable
	}
	snapshot := domain.Snapshot{AuthID: subject, AccountStatus: status, Permissions: permissions, Revision: raw.Lookup("permissionRevision").Int64()}
	_, err = snapshot.State()
	return snapshot, err
}

func (r *ScriptMaintainerPermissionRepository) Get(ctx context.Context, actor, subject string) (domain.State, error) {
	var state domain.State
	err := r.transaction(ctx, actor, func(tx context.Context) error {
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

func (r *ScriptMaintainerPermissionRepository) Manage(ctx context.Context, command domain.Command) (domain.State, error) {
	var state domain.State
	eventID := uuid.NewString()
	err := r.transaction(ctx, command.ActorAuthID, func(tx context.Context) error {
		before, err := r.snapshot(tx, command.SubjectAuthID)
		if err != nil {
			return err
		}
		after, err := domain.Change(before, command)
		if err != nil {
			return err
		}
		if command.Action == "GRANT" {
			if !r.recoveryReady {
				return domain.ErrGrantBlocked
			}
			_, revision, err := ReadPrimaryEmailTx(tx, r.auth.database, command.SubjectAuthID)
			if err != nil {
				return err
			}
			if revision <= 0 {
				return domain.ErrGrantBlocked
			}
		}
		err = r.auth.writeManagedPermissionTx(tx, managedPermissionChange{
			subject: before.AuthID, status: before.AccountStatus, actor: command.ActorAuthID, permission: command.Permission,
			action: command.Action, reason: command.Reason, eventID: eventID,
			beforeRevision: before.Revision, afterRevision: after.Revision, beforePermissions: before.Permissions, afterPermissions: after.Permissions,
		})
		if errors.Is(err, errManagedPermissionConflict) {
			return domain.ErrConflict
		}
		if err != nil {
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
