package mongo

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/applicationclosure/domain"
)

const (
	ApplicationClosureTombstoneCollection     = "application_closure_tombstones"
	ApplicationClosureAuditCollection         = "application_closure_audit_events"
	ApplicationClosureSecurityEventCollection = "application_closure_security_events"
)

type applicationClosureDocument struct {
	ApplicationID    string    `bson:"applicationId"`
	ClosureID        string    `bson:"closureId"`
	ClosingStartedAt time.Time `bson:"closingStartedAt"`
	ReceiptID        string    `bson:"receiptId"`
	AppliedAt        time.Time `bson:"appliedAt"`
	CallerServiceID  string    `bson:"callerServiceId"`
}

type applicationClosureAuditDocument struct {
	ApplicationID    string    `bson:"applicationId"`
	ClosureID        string    `bson:"closureId"`
	ReceiptID        string    `bson:"receiptId"`
	ClosingStartedAt time.Time `bson:"closingStartedAt"`
	AppliedAt        time.Time `bson:"appliedAt"`
	CallerServiceID  string    `bson:"callerServiceId"`
	Action           string    `bson:"action"`
}

func (v applicationClosureDocument) domain() d.Tombstone {
	return d.Tombstone{ApplicationID: v.ApplicationID, ClosureID: v.ClosureID, ClosingStartedAt: v.ClosingStartedAt, ReceiptID: v.ReceiptID, AppliedAt: v.AppliedAt, CallerServiceID: v.CallerServiceID}
}

type ApplicationClosureRepository struct{ auth *AuthenticationRepository }

func NewApplicationClosureRepository(auth *AuthenticationRepository) (*ApplicationClosureRepository, error) {
	if auth == nil {
		return nil, d.ErrUnavailable
	}
	return &ApplicationClosureRepository{auth: auth}, nil
}

func EnsureApplicationClosureSchema(ctx context.Context, db *m.Database) error {
	if db == nil {
		return d.ErrUnavailable
	}
	validator := bson.M{"$jsonSchema": bson.M{"bsonType": "object", "required": bson.A{"applicationId", "closureId", "closingStartedAt", "receiptId", "appliedAt", "callerServiceId"}, "additionalProperties": false, "properties": bson.M{
		"_id": bson.M{"bsonType": "objectId"}, "applicationId": bson.M{"bsonType": "string"}, "closureId": bson.M{"bsonType": "string"},
		"closingStartedAt": bson.M{"bsonType": "date"}, "receiptId": bson.M{"bsonType": "string"}, "appliedAt": bson.M{"bsonType": "date"}, "callerServiceId": bson.M{"bsonType": "string"},
	}}}
	err := db.CreateCollection(ctx, ApplicationClosureTombstoneCollection, options.CreateCollection().SetValidator(validator).SetValidationLevel("strict"))
	var command m.CommandError
	if err != nil && (!errors.As(err, &command) || command.Code != 48) {
		return err
	}
	if err != nil {
		if err = db.RunCommand(ctx, bson.D{{Key: "collMod", Value: ApplicationClosureTombstoneCollection}, {Key: "validator", Value: validator}, {Key: "validationLevel", Value: "strict"}}).Err(); err != nil {
			return err
		}
	}
	auditValidator := bson.M{"$jsonSchema": bson.M{"bsonType": "object", "required": bson.A{"applicationId", "closureId", "closingStartedAt", "receiptId", "appliedAt", "callerServiceId", "action"}, "additionalProperties": false, "properties": bson.M{
		"_id": bson.M{"bsonType": "objectId"}, "applicationId": bson.M{"bsonType": "string"}, "closureId": bson.M{"bsonType": "string"},
		"closingStartedAt": bson.M{"bsonType": "date"}, "receiptId": bson.M{"bsonType": "string"}, "appliedAt": bson.M{"bsonType": "date"}, "callerServiceId": bson.M{"bsonType": "string"}, "action": bson.M{"enum": bson.A{"APPLICATION_CLOSED"}},
	}}}
	err = db.CreateCollection(ctx, ApplicationClosureAuditCollection, options.CreateCollection().SetValidator(auditValidator).SetValidationLevel("strict"))
	if err != nil && (!errors.As(err, &command) || command.Code != 48) {
		return err
	}
	if err != nil {
		if err = db.RunCommand(ctx, bson.D{{Key: "collMod", Value: ApplicationClosureAuditCollection}, {Key: "validator", Value: auditValidator}, {Key: "validationLevel", Value: "strict"}}).Err(); err != nil {
			return err
		}
	}
	securityValidator := bson.M{"$jsonSchema": bson.M{"bsonType": "object", "required": bson.A{"applicationId", "closureId", "closingStartedAt", "callerServiceId", "observedAt", "reason"}, "additionalProperties": false, "properties": bson.M{
		"_id": bson.M{"bsonType": "objectId"}, "applicationId": bson.M{"bsonType": "string"}, "closureId": bson.M{"bsonType": "string"}, "closingStartedAt": bson.M{"bsonType": "date"}, "callerServiceId": bson.M{"bsonType": "string"}, "observedAt": bson.M{"bsonType": "date"}, "reason": bson.M{"enum": bson.A{"APPLICATION_CLOSURE_BINDING_CONFLICT"}},
	}}}
	err = db.CreateCollection(ctx, ApplicationClosureSecurityEventCollection, options.CreateCollection().SetValidator(securityValidator).SetValidationLevel("strict"))
	if err != nil && (!errors.As(err, &command) || command.Code != 48) {
		return err
	}
	if err != nil {
		if err = db.RunCommand(ctx, bson.D{{Key: "collMod", Value: ApplicationClosureSecurityEventCollection}, {Key: "validator", Value: securityValidator}, {Key: "validationLevel", Value: "strict"}}).Err(); err != nil {
			return err
		}
	}
	_, err = db.Collection(ApplicationClosureTombstoneCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "applicationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_closure_application_unique")},
		{Keys: bson.D{{Key: "closureId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_closure_id_unique")},
		{Keys: bson.D{{Key: "receiptId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_closure_receipt_unique")},
	})
	if err != nil {
		return err
	}
	_, err = db.Collection(ApplicationClosureAuditCollection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: "applicationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_closure_audit_unique")})
	if err != nil {
		return err
	}
	_, err = db.Collection(ApplicationClosureSecurityEventCollection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: "applicationId", Value: 1}, {Key: "closureId", Value: 1}, {Key: "closingStartedAt", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_closure_conflict_unique")})
	return err
}

func validClosure(v applicationClosureDocument) bool {
	return v.ApplicationID != "" && strings.TrimSpace(v.ApplicationID) == v.ApplicationID && canonicalClosureID(v.ClosureID) && canonicalClosureID(v.ReceiptID) && strings.TrimSpace(v.CallerServiceID) == v.CallerServiceID && v.CallerServiceID != "" && !v.ClosingStartedAt.IsZero() && !v.AppliedAt.IsZero()
}

func canonicalClosureID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && strings.ToLower(id.String()) == value
}

func validClosureAudit(v applicationClosureAuditDocument) bool {
	return validClosure(applicationClosureDocument{ApplicationID: v.ApplicationID, ClosureID: v.ClosureID, ReceiptID: v.ReceiptID, ClosingStartedAt: v.ClosingStartedAt, AppliedAt: v.AppliedAt, CallerServiceID: v.CallerServiceID}) && v.Action == "APPLICATION_CLOSED"
}

func closureAuditMatches(t applicationClosureDocument, a applicationClosureAuditDocument) bool {
	return t.ApplicationID == a.ApplicationID && t.ClosureID == a.ClosureID && t.ReceiptID == a.ReceiptID && t.CallerServiceID == a.CallerServiceID && t.ClosingStartedAt.Equal(a.ClosingStartedAt) && t.AppliedAt.Equal(a.AppliedAt)
}

func (r *ApplicationClosureRepository) recordConflict(ctx context.Context, app, closure string, started time.Time, caller string) error {
	_, err := r.auth.database.Collection(ApplicationClosureSecurityEventCollection).InsertOne(ctx, bson.M{"applicationId": app, "closureId": closure, "closingStartedAt": started, "callerServiceId": caller, "observedAt": time.Now().UTC().Truncate(time.Millisecond), "reason": "APPLICATION_CLOSURE_BINDING_CONFLICT"})
	if m.IsDuplicateKeyError(err) {
		return nil
	}
	return err
}

// VerifyApplicationClosureConsistency rejects traffic after a partial or corrupt
// restore. The audit receipt and permanent tombstone are a one-to-one fact.
func VerifyApplicationClosureConsistency(ctx context.Context, db *m.Database) error {
	if db == nil {
		return d.ErrUnavailable
	}
	cursor, err := db.Collection(ApplicationClosureTombstoneCollection).Find(ctx, bson.M{})
	if err != nil {
		return d.ErrUnavailable
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var tombstone applicationClosureDocument
		if cursor.Decode(&tombstone) != nil || !validClosure(tombstone) {
			return d.ErrInconsistent
		}
		var audit applicationClosureAuditDocument
		if err = db.Collection(ApplicationClosureAuditCollection).FindOne(ctx, bson.M{"applicationId": tombstone.ApplicationID}).Decode(&audit); err != nil || !validClosureAudit(audit) || !closureAuditMatches(tombstone, audit) {
			return d.ErrInconsistent
		}
	}
	if cursor.Err() != nil {
		return d.ErrUnavailable
	}
	cursor, err = db.Collection(ApplicationClosureAuditCollection).Find(ctx, bson.M{})
	if err != nil {
		return d.ErrUnavailable
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var audit applicationClosureAuditDocument
		if cursor.Decode(&audit) != nil || !validClosureAudit(audit) {
			return d.ErrInconsistent
		}
		var tombstone applicationClosureDocument
		if err = db.Collection(ApplicationClosureTombstoneCollection).FindOne(ctx, bson.M{"applicationId": audit.ApplicationID}).Decode(&tombstone); err != nil || !validClosure(tombstone) || !closureAuditMatches(tombstone, audit) {
			return d.ErrInconsistent
		}
	}
	if cursor.Err() != nil {
		return d.ErrUnavailable
	}
	return nil
}

func (r *ApplicationClosureRepository) Apply(ctx context.Context, app, closure string, started time.Time, receipt, caller string, applied time.Time) (d.Tombstone, error) {
	var out d.Tombstone
	var semantic error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		semantic = nil
		var existing applicationClosureDocument
		e := r.auth.database.Collection(ApplicationClosureTombstoneCollection).FindOne(tx, bson.M{"applicationId": app}).Decode(&existing)
		if e == nil {
			if !validClosure(existing) {
				semantic = d.ErrInconsistent
				return errors.New("invalid closure tombstone")
			}
			if existing.ClosureID != closure || !existing.ClosingStartedAt.Equal(started) {
				semantic = d.ErrConflict
				return errors.New("closure binding conflict")
			}
			out = existing.domain()
			return nil
		}
		if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		doc := applicationClosureDocument{ApplicationID: app, ClosureID: closure, ClosingStartedAt: started, ReceiptID: receipt, AppliedAt: applied, CallerServiceID: caller}
		if _, e = r.auth.database.Collection(ApplicationClosureTombstoneCollection).InsertOne(tx, doc); e != nil {
			if m.IsDuplicateKeyError(e) {
				semantic = d.ErrConflict
				return errors.New("closure uniqueness conflict")
			}
			return e
		}
		if _, e = r.auth.database.Collection(ApplicationClosureAuditCollection).InsertOne(tx, bson.M{"applicationId": app, "closureId": closure, "receiptId": receipt, "closingStartedAt": started, "appliedAt": applied, "callerServiceId": caller, "action": "APPLICATION_CLOSED"}); e != nil {
			return e
		}
		out = doc.domain()
		return nil
	})
	if semantic != nil {
		if errors.Is(semantic, d.ErrConflict) {
			var existing applicationClosureDocument
			if e := r.auth.database.Collection(ApplicationClosureTombstoneCollection).FindOne(ctx, bson.M{"applicationId": app}).Decode(&existing); e == nil && validClosure(existing) && existing.ClosureID == closure && existing.ClosingStartedAt.Equal(started) {
				return existing.domain(), nil
			}
			if e := r.recordConflict(ctx, app, closure, started, caller); e != nil {
				return d.Tombstone{}, d.ErrUnavailable
			}
		}
		return d.Tombstone{}, semantic
	}
	if err != nil {
		return d.Tombstone{}, d.ErrUnavailable
	}
	return out, nil
}

func (r *ApplicationClosureRepository) Get(ctx context.Context, app, closure string) (d.Tombstone, error) {
	var doc applicationClosureDocument
	err := r.auth.database.Collection(ApplicationClosureTombstoneCollection).FindOne(ctx, bson.M{"applicationId": app, "closureId": closure}).Decode(&doc)
	if errors.Is(err, m.ErrNoDocuments) {
		return d.Tombstone{}, d.ErrNotFound
	}
	if err != nil {
		return d.Tombstone{}, d.ErrUnavailable
	}
	if !validClosure(doc) {
		return d.Tombstone{}, d.ErrInconsistent
	}
	return doc.domain(), nil
}

func (r *ApplicationClosureRepository) IsClosedTx(ctx context.Context, app string) (bool, error) {
	var doc applicationClosureDocument
	err := r.auth.database.Collection(ApplicationClosureTombstoneCollection).FindOne(ctx, bson.M{"applicationId": app}).Decode(&doc)
	if errors.Is(err, m.ErrNoDocuments) {
		return false, nil
	}
	if err != nil || !validClosure(doc) {
		return false, d.ErrUnavailable
	}
	return true, nil
}
