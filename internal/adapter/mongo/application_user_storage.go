package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/oauth/domain"
)

const (
	ApplicationUserStorageCollection      = "auth_application_user_storage"
	ApplicationUserStorageAuditCollection = "auth_application_user_storage_audit"
)

type applicationUserStorageDocument struct {
	AuthID        string           `bson:"authId"`
	ApplicationID string           `bson:"applicationId"`
	Channel       string           `bson:"channel"`
	Revision      int64            `bson:"revision"`
	Entries       []d.StorageEntry `bson:"entries"`
	UpdatedAt     bson.DateTime    `bson:"updatedAt"`
}

func (tx *oauthTx) ApplicationUserStorage(authID, applicationID, channel string) (d.StorageNamespace, error) {
	var doc applicationUserStorageDocument
	err := tx.r.db.Collection(ApplicationUserStorageCollection).FindOne(tx.ctx, bson.M{"authId": authID, "applicationId": applicationID, "channel": channel}).Decode(&doc)
	if errors.Is(err, m.ErrNoDocuments) {
		return d.StorageNamespace{}, d.ErrNotFound
	}
	if err != nil {
		return d.StorageNamespace{}, d.ErrUnavailable
	}
	return d.StorageNamespace{AuthID: doc.AuthID, ApplicationID: doc.ApplicationID, Channel: doc.Channel, Revision: doc.Revision, Entries: doc.Entries, UpdatedAt: doc.UpdatedAt.Time()}, nil
}

func (tx *oauthTx) SaveApplicationUserStorage(expectedRevision int64, namespace d.StorageNamespace) error {
	doc := applicationUserStorageDocument{AuthID: namespace.AuthID, ApplicationID: namespace.ApplicationID, Channel: namespace.Channel, Revision: namespace.Revision, Entries: namespace.Entries, UpdatedAt: bson.NewDateTimeFromTime(namespace.UpdatedAt)}
	filter := bson.M{"authId": namespace.AuthID, "applicationId": namespace.ApplicationID, "channel": namespace.Channel, "revision": expectedRevision}
	result, err := tx.r.db.Collection(ApplicationUserStorageCollection).ReplaceOne(tx.ctx, filter, doc, options.Replace().SetUpsert(expectedRevision == 0))
	if m.IsDuplicateKeyError(err) {
		return d.ErrStorageConflict
	}
	if err != nil {
		return d.ErrUnavailable
	}
	if result.MatchedCount == 0 && result.UpsertedCount == 0 {
		return d.ErrStorageConflict
	}
	return nil
}

func (tx *oauthTx) ClearApplicationUserStorage(authID, applicationID string, at time.Time) (bool, error) {
	result, err := tx.r.db.Collection(ApplicationUserStorageCollection).DeleteMany(tx.ctx, bson.M{"authId": authID, "applicationId": applicationID})
	if err != nil {
		return false, d.ErrUnavailable
	}
	if result.DeletedCount == 0 {
		return false, nil
	}
	_, err = tx.r.db.Collection(ApplicationUserStorageAuditCollection).InsertOne(tx.ctx, bson.M{"authId": authID, "applicationId": applicationID, "action": "USER_CLEARED", "occurredAt": at, "namespaceCount": result.DeletedCount})
	if err != nil {
		return false, d.ErrUnavailable
	}
	return true, nil
}

func EnsureApplicationUserStorageSchema(ctx context.Context, db *m.Database) error {
	if err := db.CreateCollection(ctx, ApplicationUserStorageCollection); err != nil {
		var commandError m.CommandError
		if !errors.As(err, &commandError) || commandError.Code != 48 {
			return err
		}
	}
	if err := db.CreateCollection(ctx, ApplicationUserStorageAuditCollection); err != nil {
		var commandError m.CommandError
		if !errors.As(err, &commandError) || commandError.Code != 48 {
			return err
		}
	}
	_, err := db.Collection(ApplicationUserStorageCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "applicationId", Value: 1}, {Key: "channel", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_user_storage_namespace")},
		{Keys: bson.D{{Key: "applicationId", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("application_user_storage_application_cleanup")},
		{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "_id", Value: 1}}, Options: options.Index().SetName("application_user_storage_account_cleanup")},
	})
	if err != nil {
		return err
	}
	_, err = db.Collection(ApplicationUserStorageAuditCollection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "occurredAt", Value: 1}}, Options: options.Index().SetName("application_user_storage_audit_subject")})
	return err
}
