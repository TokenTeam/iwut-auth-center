package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	"time"
)

// CancelPendingOwnerExitsTx persists the terminal decision/outbox in the caller's
// global authentication transaction. Delivery is the UC024 coordinator's job;
// a failed App RPC must never roll back governance or invent a cancelled result.
func (a *AuthenticationRepository) CancelPendingOwnerExitsTx(ctx context.Context, authID, reason string, now time.Time) error {
	if authID == "" || reason == "" || now.IsZero() {
		return errors.New("invalid owner exit cancellation")
	}
	_, err := a.database.Collection("auth_account_owner_exit_operations").UpdateMany(ctx, bson.M{"authId": authID, "decision": "PENDING"}, bson.M{"$set": bson.M{"decision": "CANCELLED", "decidedAt": now, "cancellationReason": reason, "notificationPending": true, "nextAttemptAt": now}})
	return err
}
