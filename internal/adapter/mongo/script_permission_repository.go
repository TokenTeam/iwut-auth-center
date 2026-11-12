package mongo

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"

	admin "iwut-auth-center/internal/administrator/domain"
	authport "iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/scriptpermission/domain"
)

type ScriptPermissionRepository struct {
	auth          *AuthenticationRepository
	recoveryReady bool
}

func NewScriptPermissionRepository(auth *AuthenticationRepository, recoveryReady bool) *ScriptPermissionRepository {
	return &ScriptPermissionRepository{auth: auth, recoveryReady: recoveryReady}
}

func (r *ScriptPermissionRepository) transaction(ctx context.Context, actor string, run func(context.Context) error) error {
	return r.withTransaction(ctx, func(tx context.Context) error {
		switch err := r.auth.RequireAdministratorTx(tx, actor); {
		case errors.Is(err, admin.ErrIdentity):
			return domain.ErrIdentity
		case errors.Is(err, admin.ErrForbidden):
			return domain.ErrForbidden
		case err != nil:
			return err
		default:
			return run(tx)
		}
	})
}

func (r *ScriptPermissionRepository) withTransaction(ctx context.Context, run func(context.Context) error) error {
	var semantic error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		semantic = run(tx)
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

// GetOwn uses the verified current identity, not the administrator target reader.
// Neither administrator initialization nor email/recovery participates in it.
func (r *ScriptPermissionRepository) GetOwn(ctx context.Context, actor string) (domain.State, error) {
	var state domain.State
	err := r.withTransaction(ctx, func(tx context.Context) error {
		var raw bson.Raw
		err := r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": actor}).Decode(&raw)
		if errors.Is(err, drivermongo.ErrNoDocuments) {
			return domain.ErrIdentity
		}
		if err != nil || !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString}) || raw.Lookup("authId").StringValue() != actor {
			return domain.ErrUnavailable
		}
		switch raw.Lookup("principalType").StringValue() {
		case "SYSTEM":
			return domain.ErrIdentity
		case "USER":
		default:
			return domain.ErrUnavailable
		}
		status, ok := raw.Lookup("accountStatus").StringValueOK()
		if !ok || (status != "ACTIVE" && status != "DISABLED" && status != "CLOSED") {
			return domain.ErrUnavailable
		}
		if status == "CLOSED" {
			if !validClosedPrincipal(raw) {
				return domain.ErrUnavailable
			}
			return domain.ErrIdentity
		}
		if err = r.auth.ConfirmIdentityTx(tx, actor); err != nil {
			if errors.Is(err, authport.ErrAuthenticationFailed) {
				return domain.ErrIdentity
			}
			return domain.ErrUnavailable
		}
		if !identityFields(raw, map[string]bson.Type{"permissions": bson.TypeArray, "permissionRevision": bson.TypeInt64}) {
			return domain.ErrUnavailable
		}
		permissions, err := adminPermissions(raw.Lookup("permissions"))
		if err != nil {
			return domain.ErrUnavailable
		}
		snapshot := domain.Snapshot{AuthID: actor, AccountStatus: status, Permissions: permissions, Revision: raw.Lookup("permissionRevision").Int64()}
		state, err = snapshot.State()
		return err
	})
	if err != nil {
		return domain.State{}, err
	}
	return state, nil
}

func (r *ScriptPermissionRepository) snapshot(ctx context.Context, subject string) (domain.Snapshot, error) {
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

func (r *ScriptPermissionRepository) Get(ctx context.Context, actor, subject string) (domain.State, error) {
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

func (r *ScriptPermissionRepository) Manage(ctx context.Context, command domain.Command) (domain.State, error) {
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
