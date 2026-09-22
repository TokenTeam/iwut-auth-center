package mongo

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
	"iwut-auth-center/internal/registration/domain"
	"iwut-auth-center/internal/registration/port"
)

const AssociationCollection = "auth_student_associations"
const AssociationMemberCollection = "auth_student_association_members"

type associationDocument struct {
	ID            any    `bson:"_id,omitempty"`
	AssociationID string `bson:"associationId"`
	SchemeVersion string `bson:"schemeVersion"`
	KeyVersion    string `bson:"keyVersion"`
	LookupKey     []byte `bson:"lookupKey"`
	Nonce         []byte `bson:"nonce"`
	Ciphertext    []byte `bson:"ciphertext"`
}

func (d associationDocument) association() domain.Association {
	return domain.Association{AssociationID: d.AssociationID, SealedAssociation: domain.SealedAssociation{SchemeVersion: d.SchemeVersion, KeyVersion: d.KeyVersion, LookupKey: d.LookupKey, Nonce: d.Nonce, Ciphertext: d.Ciphertext}}
}
func associationDoc(a domain.Association) associationDocument {
	return associationDocument{AssociationID: a.AssociationID, SchemeVersion: a.SchemeVersion, KeyVersion: a.KeyVersion, LookupKey: a.LookupKey, Nonce: a.Nonce, Ciphertext: a.Ciphertext}
}

type AssociationMigrationRepository struct {
	db                 *drivermongo.Database
	groups, operations *drivermongo.Collection
}

func NewAssociationMigrationRepository(db *drivermongo.Database) (*AssociationMigrationRepository, error) {
	if db == nil {
		return nil, errors.New("association migration: missing database")
	}
	// Majority+journal is at least w:1,j:true and preserves durability on replicas.
	journal := true
	opts := options.Collection().SetWriteConcern(&writeconcern.WriteConcern{W: "majority", Journal: &journal})
	return &AssociationMigrationRepository{db: db, groups: db.Collection(AssociationCollection, opts), operations: db.Collection("auth_authentication_operations", opts)}, nil
}

func EnsureAssociationSchema(ctx context.Context, db *drivermongo.Database) error {
	if db == nil {
		return errors.New("association schema: missing database")
	}
	_, err := db.Collection(AssociationCollection).Indexes().CreateMany(ctx, []drivermongo.IndexModel{
		{Keys: bson.D{{Key: "associationId", Value: 1}}, Options: options.Index().SetName("association_id_unique").SetUnique(true)},
		{Keys: bson.D{{Key: "keyVersion", Value: 1}, {Key: "lookupKey", Value: 1}}, Options: options.Index().SetName("association_lookup_unique").SetUnique(true)},
	})
	if err != nil {
		return errors.New("association schema: cannot ensure group indexes")
	}
	_, err = db.Collection(AssociationMemberCollection).Indexes().CreateOne(ctx, drivermongo.IndexModel{Keys: bson.D{{Key: "authId", Value: 1}}, Options: options.Index().SetName("association_member_auth_id_unique").SetUnique(true)})
	if err != nil {
		return errors.New("association schema: cannot ensure member index")
	}
	return nil
}
func (r *AssociationMigrationRepository) EnsureMigrationSchema(ctx context.Context) error {
	return EnsureAssociationSchema(ctx, r.db)
}

func (r *AssociationMigrationRepository) PrepareOperations(ctx context.Context, rotate bool, now time.Time) error {
	filter := bson.M{"purpose": "REGISTER", "status": "PENDING"}
	if !rotate {
		filter["expiresAt"] = bson.M{"$lte": now}
	}
	_, err := r.operations.UpdateMany(ctx, filter, bson.M{"$set": bson.M{"status": "CLOSED"}, "$unset": bson.M{"nonce": "", "ciphertext": "", "lookupKey": ""}})
	if err != nil {
		return errors.New("association migration: cannot close operations")
	}
	_, err = r.operations.UpdateMany(ctx, bson.M{"purpose": "REGISTER", "status": bson.M{"$ne": "PENDING"}}, bson.M{"$unset": bson.M{"nonce": "", "ciphertext": "", "lookupKey": ""}})
	if err != nil {
		return errors.New("association migration: cannot clear operations")
	}
	return nil
}

func (r *AssociationMigrationRepository) ValidateOperationSnapshots(ctx context.Context, c port.AssociationCipher, now time.Time) error {
	cur, err := r.operations.Find(ctx, bson.M{"purpose": "REGISTER"}, options.Find().SetBatchSize(500))
	if err != nil {
		return errors.New("association migration: operation scan unavailable")
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var d struct {
			OperationID   string    `bson:"operationId"`
			Status        string    `bson:"status"`
			ExpiresAt     time.Time `bson:"expiresAt"`
			SchemeVersion string    `bson:"schemeVersion"`
			KeyVersion    string    `bson:"keyVersion"`
			LookupKey     []byte    `bson:"lookupKey"`
			Nonce         []byte    `bson:"nonce"`
			Ciphertext    []byte    `bson:"ciphertext"`
		}
		if cur.Decode(&d) != nil {
			return errors.New("association migration: invalid operation record")
		}
		if d.Status != "PENDING" || !now.Before(d.ExpiresAt) {
			if len(d.Ciphertext) > 0 || len(d.Nonce) > 0 || len(d.LookupKey) > 0 {
				return errors.New("association migration: stale operation ciphertext")
			}
			continue
		}
		if c.PreviousVersion() != "" || d.KeyVersion != c.CurrentVersion() {
			return errors.New("association migration: invalid pending key version")
		}
		plain, err := c.Open("operation", d.OperationID, domain.SealedAssociation{SchemeVersion: d.SchemeVersion, KeyVersion: d.KeyVersion, LookupKey: d.LookupKey, Nonce: d.Nonce, Ciphertext: d.Ciphertext})
		clear(plain)
		if err != nil {
			return errors.New("association migration: operation authentication failed")
		}
	}
	if cur.Err() != nil {
		return errors.New("association migration: operation scan failed")
	}
	return nil
}

func (r *AssociationMigrationRepository) CountAssociations(ctx context.Context) (int64, error) {
	n, e := r.groups.CountDocuments(ctx, bson.M{})
	if e != nil {
		return 0, errors.New("association migration: count failed")
	}
	return n, nil
}
func (r *AssociationMigrationRepository) ScanAssociations(ctx context.Context, visit func(port.MigrationRecord) error) error {
	cur, err := r.groups.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}).SetBatchSize(500))
	if err != nil {
		return errors.New("association migration: scan failed")
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var d associationDocument
		if cur.Decode(&d) != nil {
			return errors.New("association migration: invalid group")
		}
		if err := visit(port.MigrationRecord{Key: d.ID, Association: d.association()}); err != nil {
			return err
		}
	}
	if cur.Err() != nil {
		return errors.New("association migration: scan interrupted")
	}
	return nil
}
func (r *AssociationMigrationRepository) WriteMigrationBatch(ctx context.Context, updates []port.MigrationUpdate) error {
	if len(updates) == 0 || len(updates) > 500 {
		return errors.New("association migration: invalid batch size")
	}
	models := make([]drivermongo.WriteModel, 0, len(updates))
	for _, u := range updates {
		models = append(models, drivermongo.NewUpdateOneModel().SetFilter(bson.M{"_id": u.Key, "keyVersion": u.SourceVersion}).SetUpdate(bson.M{"$set": bson.M{"keyVersion": u.Target.KeyVersion, "lookupKey": u.Target.LookupKey, "nonce": u.Target.Nonce, "ciphertext": u.Target.Ciphertext}}).SetUpsert(false))
	}
	result, err := r.groups.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(true))
	if err != nil {
		return errors.New("association migration: batch failed; restart with same keys")
	}
	if result.MatchedCount != int64(len(updates)) || result.ModifiedCount != int64(len(updates)) {
		return errors.New("association migration: batch count mismatch")
	}
	return nil
}
