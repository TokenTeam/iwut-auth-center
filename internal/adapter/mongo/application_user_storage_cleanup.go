package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	closured "iwut-auth-center/internal/applicationclosure/domain"
)

const ApplicationUserStorageCleanupTaskCollection = "auth_application_user_storage_cleanup_tasks"

type applicationUserStorageCleanupTask struct {
	ApplicationID string     `bson:"applicationId"`
	ClosureID     string     `bson:"closureId"`
	CreatedAt     time.Time  `bson:"createdAt"`
	LastAttemptAt *time.Time `bson:"lastAttemptAt,omitempty"`
	CompletedAt   *time.Time `bson:"completedAt,omitempty"`
	DeletedCount  int64      `bson:"deletedCount"`
	Complete      bool       `bson:"complete"`
}

func EnsureApplicationUserStorageCleanupSchema(ctx context.Context, db *m.Database) error {
	if err := db.CreateCollection(ctx, ApplicationUserStorageCleanupTaskCollection); err != nil {
		var commandError m.CommandError
		if !errors.As(err, &commandError) || commandError.Code != 48 {
			return err
		}
	}
	_, err := db.Collection(ApplicationUserStorageCleanupTaskCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "applicationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_storage_cleanup_application")},
		{Keys: bson.D{{Key: "complete", Value: 1}, {Key: "lastAttemptAt", Value: 1}}, Options: options.Index().SetName("application_storage_cleanup_pending")},
	})
	return err
}

func ensureApplicationUserStorageCleanupTaskTx(ctx context.Context, db *m.Database, applicationID, closureID string, at time.Time) error {
	var existing applicationUserStorageCleanupTask
	err := db.Collection(ApplicationUserStorageCleanupTaskCollection).FindOne(ctx, bson.M{"applicationId": applicationID}).Decode(&existing)
	if err == nil {
		if existing.ApplicationID != applicationID || existing.ClosureID != closureID || existing.CreatedAt.IsZero() {
			return closured.ErrInconsistent
		}
		return nil
	}
	if !errors.Is(err, m.ErrNoDocuments) {
		return err
	}
	_, err = db.Collection(ApplicationUserStorageCleanupTaskCollection).InsertOne(ctx, applicationUserStorageCleanupTask{ApplicationID: applicationID, ClosureID: closureID, CreatedAt: at, Complete: false})
	return err
}

func ReconcileApplicationUserStorageCleanupTasks(ctx context.Context, auth *AuthenticationRepository) error {
	if auth == nil {
		return closured.ErrUnavailable
	}
	cursor, err := auth.database.Collection(ApplicationClosureTombstoneCollection).Find(ctx, bson.M{})
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var tombstone applicationClosureDocument
		if cursor.Decode(&tombstone) != nil || !validClosure(tombstone) {
			return closured.ErrInconsistent
		}
		if err = auth.WithAuthTransaction(ctx, func(tx context.Context) error {
			return ensureApplicationUserStorageCleanupTaskTx(tx, auth.database, tombstone.ApplicationID, tombstone.ClosureID, tombstone.AppliedAt)
		}); err != nil {
			return err
		}
	}
	return cursor.Err()
}

func VerifyApplicationUserStorageCleanupConsistency(ctx context.Context, db *m.Database) error {
	if db == nil {
		return closured.ErrUnavailable
	}
	cursor, err := db.Collection(ApplicationUserStorageCleanupTaskCollection).Find(ctx, bson.M{})
	if err != nil {
		return closured.ErrUnavailable
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var task applicationUserStorageCleanupTask
		if cursor.Decode(&task) != nil || task.ApplicationID == "" || task.ClosureID == "" || task.CreatedAt.IsZero() || task.DeletedCount < 0 || task.Complete != (task.CompletedAt != nil) || task.CompletedAt != nil && task.CompletedAt.IsZero() || task.LastAttemptAt != nil && task.LastAttemptAt.IsZero() {
			return closured.ErrInconsistent
		}
		var tombstone applicationClosureDocument
		if err = db.Collection(ApplicationClosureTombstoneCollection).FindOne(ctx, bson.M{"applicationId": task.ApplicationID}).Decode(&tombstone); err != nil || !validClosure(tombstone) || tombstone.ClosureID != task.ClosureID || !tombstone.AppliedAt.Equal(task.CreatedAt) {
			return closured.ErrInconsistent
		}
	}
	if cursor.Err() != nil {
		return closured.ErrUnavailable
	}
	return nil
}

// Tick deletes one bounded batch for one closed Application. Tombstones remain
// permanent and access is already denied before physical cleanup begins.
func (r *ApplicationClosureRepository) Tick(ctx context.Context) error {
	var task applicationUserStorageCleanupTask
	err := r.auth.database.Collection(ApplicationUserStorageCleanupTaskCollection).FindOne(ctx, bson.M{"complete": false}, options.FindOne().SetSort(bson.D{{Key: "lastAttemptAt", Value: 1}, {Key: "applicationId", Value: 1}})).Decode(&task)
	if errors.Is(err, m.ErrNoDocuments) {
		return nil
	}
	if err != nil || task.ApplicationID == "" || task.ClosureID == "" || task.CreatedAt.IsZero() {
		return closured.ErrUnavailable
	}
	return r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		closed, err := r.IsClosedTx(tx, task.ApplicationID)
		if err != nil || !closed {
			return closured.ErrInconsistent
		}
		cursor, err := r.auth.database.Collection(ApplicationUserStorageCollection).Find(tx, bson.M{"applicationId": task.ApplicationID}, options.Find().SetProjection(bson.M{"_id": 1}).SetLimit(500))
		if err != nil {
			return err
		}
		var ids []any
		for cursor.Next(tx) {
			var doc bson.M
			if cursor.Decode(&doc) != nil || doc["_id"] == nil {
				cursor.Close(tx)
				return closured.ErrUnavailable
			}
			ids = append(ids, doc["_id"])
		}
		if err = cursor.Err(); err != nil {
			cursor.Close(tx)
			return err
		}
		cursor.Close(tx)
		now := time.Now().UTC().Truncate(time.Millisecond)
		if len(ids) == 0 {
			result, updateErr := r.auth.database.Collection(ApplicationUserStorageCleanupTaskCollection).UpdateOne(tx, bson.M{"applicationId": task.ApplicationID, "closureId": task.ClosureID, "complete": false}, bson.M{"$set": bson.M{"complete": true, "completedAt": now, "lastAttemptAt": now}})
			if updateErr != nil || result.MatchedCount != 1 {
				return closured.ErrUnavailable
			}
			return nil
		}
		result, err := r.auth.database.Collection(ApplicationUserStorageCollection).DeleteMany(tx, bson.M{"_id": bson.M{"$in": ids}, "applicationId": task.ApplicationID})
		if err != nil {
			return err
		}
		_, err = r.auth.database.Collection(ApplicationUserStorageCleanupTaskCollection).UpdateOne(tx, bson.M{"applicationId": task.ApplicationID, "closureId": task.ClosureID, "complete": false}, bson.M{"$set": bson.M{"lastAttemptAt": now}, "$inc": bson.M{"deletedCount": result.DeletedCount}})
		return err
	})
}
