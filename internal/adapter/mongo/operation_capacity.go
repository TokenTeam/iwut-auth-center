package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	auth "iwut-auth-center/internal/authentication/domain"
	port "iwut-auth-center/internal/authentication/port"
	"time"
)

// Shared admission runs under the global Auth write fence. TTL delays cannot
// create unbounded retained storage. Only expired rows are drained, at most 64
// per collection; no pending/retained operation is evicted to admit another.
func sharedOperationCapacityTx(ctx context.Context, db *m.Database, now time.Time, maxPending int, pending bool) error {
	collections := []struct{ name, retention string }{{AuthenticationOperationCollection, "purgeAfter"}, {EmailAccountOperationCollection, "retainUntil"}, {EmailAccountMutationCollection, "retainUntil"}, {PasswordChangeCollection, "retainUntil"}, {CredentialManagementOperationCollection, "retainUntil"}, {PasswordResetCollection, "retainUntil"}, {PasswordLoginCollection, "retainUntil"}}
	var live, physical int64
	for _, spec := range collections {
		expired, err := db.Collection(spec.name).Find(ctx, bson.M{spec.retention: bson.M{"$lte": now}}, options.Find().SetProjection(bson.M{"_id": 1}).SetLimit(64))
		if err != nil {
			return err
		}
		var rows []bson.M
		if err = expired.All(ctx, &rows); err != nil {
			expired.Close(ctx)
			return err
		}
		expired.Close(ctx)
		ids := make([]any, 0, len(rows))
		for _, row := range rows {
			ids = append(ids, row["_id"])
		}
		if len(ids) > 0 {
			if _, err = db.Collection(spec.name).DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}}); err != nil {
				return err
			}
		}
		count, err := db.Collection(spec.name).CountDocuments(ctx, bson.M{}, options.Count().SetLimit(1000000-physical))
		if err != nil {
			return err
		}
		physical += count
		if physical >= 1000000 {
			return port.ErrLimitExceeded
		}
		if pending {
			count, err = db.Collection(spec.name).CountDocuments(ctx, bson.M{"status": auth.Pending, "expiresAt": bson.M{"$gt": now}}, options.Count().SetLimit(int64(maxPending)-live))
			if err != nil {
				return err
			}
			live += count
			if live >= int64(maxPending) {
				return port.ErrLimitExceeded
			}
		}
	}
	return nil
}
