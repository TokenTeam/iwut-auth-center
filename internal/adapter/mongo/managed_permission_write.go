package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var errManagedPermissionConflict = errors.New("managed permission revision changed")

type managedPermissionChange struct {
	subject, status, actor, permission, action, reason, eventID string
	beforeRevision, afterRevision                               int64
	beforePermissions, afterPermissions                         []string
}

// Both callers authorize and validate their own permission before using this
// storage primitive in the shared Auth transaction.
func (r *AuthenticationRepository) writeManagedPermissionTx(ctx context.Context, c managedPermissionChange) error {
	now := r.currentTime(time.Time{})
	attribution := bson.M{"actorType": "USER", "actorAuthId": c.actor}
	result, err := r.database.Collection(PrincipalCollection).UpdateOne(ctx,
		bson.M{"authId": c.subject, "principalType": "USER", "accountStatus": c.status, "permissionRevision": c.beforeRevision},
		bson.M{"$set": bson.M{"permissions": c.afterPermissions, "permissionRevision": c.afterRevision, "permissionUpdatedBy": attribution, "permissionUpdatedAt": now}, "$inc": bson.M{"authenticationFence": int64(1)}},
	)
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return errManagedPermissionConflict
	}
	_, err = r.database.Collection(PermissionAuditCollection).InsertOne(ctx, bson.M{
		"eventId": c.eventID, "subjectAuthId": c.subject, "actorType": "USER", "actorAuthId": c.actor,
		"action": c.action, "permission": c.permission, "reason": c.reason,
		"beforeRevision": c.beforeRevision, "afterRevision": c.afterRevision,
		"beforePermissions": c.beforePermissions, "afterPermissions": c.afterPermissions, "occurredAt": now,
	})
	return err
}
