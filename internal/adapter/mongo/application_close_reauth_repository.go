package mongo

import (
	"bytes"
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/applicationclosereauth/domain"
	authport "iwut-auth-center/internal/authentication/port"
)

const (
	ApplicationCloseReauthOperationCollection = "application_close_reauth_operations"
	ApplicationCloseReauthAuditCollection     = "application_close_reauth_audit_events"
)

type closeReauthDocument struct {
	OperationID     string    `bson:"operationid"`
	AuthID          string    `bson:"authid"`
	SessionID       string    `bson:"sessionid"`
	CredentialID    string    `bson:"credentialid"`
	ApplicationID   string    `bson:"applicationid"`
	Challenge       []byte    `bson:"challenge"`
	PublicKey       []byte    `bson:"publickey"`
	SignatureDigest []byte    `bson:"signaturedigest,omitempty"`
	AccountRevision int64     `bson:"accountrevision"`
	FailedAttempts  int64     `bson:"failedattempts"`
	State           string    `bson:"state"`
	CreatedAt       time.Time `bson:"createdat"`
	ExpiresAt       time.Time `bson:"expiresat"`
	PurgeAt         time.Time `bson:"purgeat"`
	JTI             string    `bson:"jti,omitempty"`
	AuthTime        time.Time `bson:"authtime,omitempty"`
	IssuedAt        time.Time `bson:"issuedat,omitempty"`
	NotBefore       time.Time `bson:"notbefore,omitempty"`
	ProofExpiresAt  time.Time `bson:"proofexpiresat,omitempty"`
}

func (v closeReauthDocument) domain() domain.Operation {
	return domain.Operation{OperationID: v.OperationID, AuthID: v.AuthID, SessionID: v.SessionID, CredentialID: v.CredentialID, ApplicationID: v.ApplicationID, Challenge: v.Challenge, PublicKey: v.PublicKey, SignatureDigest: v.SignatureDigest, AccountRevision: v.AccountRevision, FailedAttempts: v.FailedAttempts, State: v.State, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt, JTI: v.JTI, AuthTime: v.AuthTime, IssuedAt: v.IssuedAt, NotBefore: v.NotBefore, ProofExpiresAt: v.ProofExpiresAt}
}

type ApplicationCloseReauthRepository struct {
	auth             *AuthenticationRepository
	maxAccountWrites int64
}

func NewApplicationCloseReauthRepository(auth *AuthenticationRepository, limits ...int) (*ApplicationCloseReauthRepository, error) {
	if auth == nil {
		return nil, domain.ErrUnavailable
	}
	maxWrites := 10
	if len(limits) > 1 || len(limits) == 1 && limits[0] <= 0 {
		return nil, domain.ErrUnavailable
	}
	if len(limits) == 1 {
		maxWrites = limits[0]
	}
	return &ApplicationCloseReauthRepository{auth: auth, maxAccountWrites: int64(maxWrites)}, nil
}

func EnsureApplicationCloseReauthSchema(ctx context.Context, db *m.Database) error {
	if db == nil {
		return domain.ErrUnavailable
	}
	operationValidator := bson.M{"$jsonSchema": bson.M{"bsonType": "object", "required": bson.A{"operationid", "authid", "sessionid", "credentialid", "applicationid", "challenge", "publickey", "accountrevision", "failedattempts", "state", "createdat", "expiresat", "purgeat"}, "additionalProperties": false, "properties": bson.M{
		"_id": bson.M{"bsonType": "objectId"}, "operationid": bson.M{"bsonType": "string"}, "authid": bson.M{"bsonType": "string"}, "sessionid": bson.M{"bsonType": "string"}, "credentialid": bson.M{"bsonType": "string"}, "applicationid": bson.M{"bsonType": "string"},
		"challenge": bson.M{"bsonType": "binData"}, "publickey": bson.M{"bsonType": "binData"}, "signaturedigest": bson.M{"bsonType": "binData"}, "accountrevision": bson.M{"bsonType": bson.A{"long", "int"}}, "failedattempts": bson.M{"bsonType": bson.A{"long", "int"}},
		"state": bson.M{"enum": bson.A{domain.Pending, domain.Completed}}, "createdat": bson.M{"bsonType": "date"}, "expiresat": bson.M{"bsonType": "date"}, "purgeat": bson.M{"bsonType": "date"}, "jti": bson.M{"bsonType": "string"}, "authtime": bson.M{"bsonType": "date"}, "issuedat": bson.M{"bsonType": "date"}, "notbefore": bson.M{"bsonType": "date"}, "proofexpiresat": bson.M{"bsonType": "date"},
	}}}
	var command m.CommandError
	err := db.CreateCollection(ctx, ApplicationCloseReauthOperationCollection, options.CreateCollection().SetValidator(operationValidator).SetValidationLevel("strict"))
	if err != nil && (!errors.As(err, &command) || command.Code != 48) {
		return err
	}
	if err != nil {
		if err = db.RunCommand(ctx, bson.D{{Key: "collMod", Value: ApplicationCloseReauthOperationCollection}, {Key: "validator", Value: operationValidator}, {Key: "validationLevel", Value: "strict"}}).Err(); err != nil {
			return err
		}
	}
	auditValidator := bson.M{"$jsonSchema": bson.M{"bsonType": "object", "required": bson.A{"operationId", "authId", "credentialId", "applicationId", "result", "occurredAt"}, "additionalProperties": false, "properties": bson.M{
		"_id": bson.M{"bsonType": "objectId"}, "operationId": bson.M{"bsonType": "string"}, "authId": bson.M{"bsonType": "string"}, "credentialId": bson.M{"bsonType": "string"}, "applicationId": bson.M{"bsonType": "string"},
		"result": bson.M{"enum": bson.A{"BEGUN", "SIGNATURE_REJECTED", "COMPLETED"}}, "attempt": bson.M{"bsonType": bson.A{"long", "int"}}, "jti": bson.M{"bsonType": "string"}, "occurredAt": bson.M{"bsonType": "date"},
	}}}
	err = db.CreateCollection(ctx, ApplicationCloseReauthAuditCollection, options.CreateCollection().SetValidator(auditValidator).SetValidationLevel("strict"))
	if err != nil && (!errors.As(err, &command) || command.Code != 48) {
		return err
	}
	if err != nil {
		if err = db.RunCommand(ctx, bson.D{{Key: "collMod", Value: ApplicationCloseReauthAuditCollection}, {Key: "validator", Value: auditValidator}, {Key: "validationLevel", Value: "strict"}}).Err(); err != nil {
			return err
		}
	}
	_, err = db.Collection(ApplicationCloseReauthOperationCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "operationid", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_close_reauth_operation_unique")},
		{Keys: bson.D{{Key: "authid", Value: 1}, {Key: "state", Value: 1}, {Key: "expiresat", Value: 1}}, Options: options.Index().SetName("application_close_reauth_owner_pending")},
		{Keys: bson.D{{Key: "purgeat", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("application_close_reauth_purge_expiry")},
		{Keys: bson.D{{Key: "jti", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true).SetName("application_close_reauth_jti_unique")},
	})
	if err != nil {
		return err
	}
	_, err = db.Collection(ApplicationCloseReauthAuditCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "operationId", Value: 1}, {Key: "result", Value: 1}, {Key: "attempt", Value: 1}}, Options: options.Index().SetUnique(true).SetName("application_close_reauth_audit_unique")},
		{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "occurredAt", Value: 1}}, Options: options.Index().SetName("application_close_reauth_account_rate")},
	})
	return err
}

func validReauth(v closeReauthDocument) bool {
	if v.OperationID == "" || v.AuthID == "" || v.SessionID == "" || v.CredentialID == "" || v.ApplicationID == "" || len(v.Challenge) != 32 || len(v.PublicKey) != 65 || v.AccountRevision <= 0 || v.FailedAttempts < 0 || v.FailedAttempts > 5 || v.CreatedAt.IsZero() || !v.ExpiresAt.After(v.CreatedAt) || v.PurgeAt.IsZero() {
		return false
	}
	if v.State == domain.Pending {
		return v.JTI == "" && len(v.SignatureDigest) == 0 && v.PurgeAt.Equal(v.ExpiresAt)
	}
	return v.State == domain.Completed && v.JTI != "" && len(v.SignatureDigest) == 32 && !v.AuthTime.IsZero() && v.IssuedAt.Equal(v.AuthTime) && v.NotBefore.Equal(v.IssuedAt.Add(-30*time.Second)) && v.ProofExpiresAt.Equal(v.IssuedAt.Add(5*time.Minute)) && v.PurgeAt.Equal(v.ProofExpiresAt)
}

func (r *ApplicationCloseReauthRepository) allowAccountWrite(tx context.Context, authID string, now time.Time) error {
	count, err := r.auth.database.Collection(ApplicationCloseReauthAuditCollection).CountDocuments(tx, bson.M{"authId": authID, "occurredAt": bson.M{"$gt": now.Add(-time.Minute)}})
	if err != nil {
		return err
	}
	if count >= r.maxAccountWrites {
		return domain.ErrRate
	}
	return nil
}

func (r *ApplicationCloseReauthRepository) semanticTx(ctx context.Context, fn func(context.Context) error) error {
	var semantic error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		semantic = fn(tx)
		if semantic != nil {
			return authport.ErrUnavailable
		}
		return nil
	})
	if semantic != nil {
		for _, known := range []error{domain.ErrInvalid, domain.ErrFailed, domain.ErrRate, domain.ErrUnavailable, domain.ErrInconsistent} {
			if errors.Is(semantic, known) {
				return known
			}
		}
		return domain.ErrUnavailable
	}
	if err != nil {
		return domain.ErrUnavailable
	}
	return nil
}

func (r *ApplicationCloseReauthRepository) session(tx context.Context, digest []byte, now time.Time) (SessionDocument, CredentialDocument, error) {
	ss, err := r.auth.CheckSessionReadTx(tx, digest, now)
	if errors.Is(err, authport.ErrSessionInvalid) {
		return SessionDocument{}, CredentialDocument{}, domain.ErrFailed
	}
	if err != nil {
		return SessionDocument{}, CredentialDocument{}, err
	}
	var session SessionDocument
	if err = r.auth.database.Collection(SessionCollection).FindOne(tx, bson.M{"sessionId": ss.SessionID}).Decode(&session); err != nil || !validSession(session) {
		return SessionDocument{}, CredentialDocument{}, domain.ErrFailed
	}
	var credential CredentialDocument
	if err = r.auth.database.Collection(CredentialCollection).FindOne(tx, bson.M{"credentialId": ss.CredentialID, "authId": ss.AuthID, "revokedAt": nil}).Decode(&credential); err != nil || !validCredential(credential) {
		return SessionDocument{}, CredentialDocument{}, domain.ErrFailed
	}
	return session, credential, nil
}

func (r *ApplicationCloseReauthRepository) Begin(ctx context.Context, digest []byte, app, operation string, challenge []byte, now, expires time.Time) (domain.Operation, error) {
	var out domain.Operation
	err := r.semanticTx(ctx, func(tx context.Context) error {
		ss, credential, err := r.session(tx, digest, now)
		if err != nil {
			return err
		}
		count, err := r.auth.database.Collection(ApplicationCloseReauthOperationCollection).CountDocuments(tx, bson.M{"authid": ss.AuthID, "state": domain.Pending, "expiresat": bson.M{"$gt": now}})
		if err != nil {
			return err
		}
		if count >= 5 {
			return domain.ErrRate
		}
		if err = r.allowAccountWrite(tx, ss.AuthID, now); err != nil {
			return err
		}
		doc := closeReauthDocument{OperationID: operation, AuthID: ss.AuthID, SessionID: ss.SessionID, CredentialID: ss.CredentialID, ApplicationID: app, Challenge: bytes.Clone(challenge), PublicKey: bytes.Clone(credential.PublicKey), AccountRevision: ss.AccountRevision, State: domain.Pending, CreatedAt: now, ExpiresAt: expires, PurgeAt: expires}
		if !validReauth(doc) {
			return domain.ErrUnavailable
		}
		if _, err = r.auth.database.Collection(ApplicationCloseReauthOperationCollection).InsertOne(tx, doc); err != nil {
			return err
		}
		if _, err = r.auth.database.Collection(ApplicationCloseReauthAuditCollection).InsertOne(tx, bson.M{"operationId": operation, "authId": ss.AuthID, "credentialId": ss.CredentialID, "applicationId": app, "result": "BEGUN", "occurredAt": now}); err != nil {
			return err
		}
		out = doc.domain()
		return nil
	})
	return out, err
}

func (r *ApplicationCloseReauthRepository) read(tx context.Context, id string) (closeReauthDocument, error) {
	var doc closeReauthDocument
	err := r.auth.database.Collection(ApplicationCloseReauthOperationCollection).FindOne(tx, bson.M{"operationid": id}).Decode(&doc)
	if errors.Is(err, m.ErrNoDocuments) {
		return doc, domain.ErrFailed
	}
	if err != nil {
		return doc, err
	}
	if !validReauth(doc) {
		return doc, domain.ErrInconsistent
	}
	return doc, nil
}

func (r *ApplicationCloseReauthRepository) ReadForComplete(ctx context.Context, digest []byte, id, app string, now time.Time) (domain.Operation, error) {
	var out domain.Operation
	err := r.semanticTx(ctx, func(tx context.Context) error {
		ss, credential, err := r.session(tx, digest, now)
		if err != nil {
			return err
		}
		doc, err := r.read(tx, id)
		if err != nil {
			return err
		}
		if doc.ApplicationID != app || doc.AuthID != ss.AuthID || doc.SessionID != ss.SessionID || doc.CredentialID != ss.CredentialID || doc.AccountRevision != ss.AccountRevision || !bytes.Equal(doc.PublicKey, credential.PublicKey) {
			return domain.ErrFailed
		}
		if doc.State == domain.Pending && (doc.FailedAttempts >= 5 || !now.Before(doc.ExpiresAt)) || doc.State == domain.Completed && !now.Before(doc.ProofExpiresAt) {
			return domain.ErrFailed
		}
		out = doc.domain()
		return nil
	})
	return out, err
}

func (r *ApplicationCloseReauthRepository) Complete(ctx context.Context, digest []byte, id, app string, signatureDigest []byte, claims domain.Claims, now time.Time) (domain.Operation, error) {
	var out domain.Operation
	err := r.semanticTx(ctx, func(tx context.Context) error {
		ss, credential, err := r.session(tx, digest, now)
		if err != nil {
			return err
		}
		doc, err := r.read(tx, id)
		if err != nil {
			return err
		}
		if doc.ApplicationID != app || doc.AuthID != ss.AuthID || doc.SessionID != ss.SessionID || doc.CredentialID != ss.CredentialID || doc.AccountRevision != ss.AccountRevision || !bytes.Equal(doc.PublicKey, credential.PublicKey) {
			return domain.ErrFailed
		}
		if doc.State == domain.Completed {
			if !bytes.Equal(doc.SignatureDigest, signatureDigest) {
				return domain.ErrFailed
			}
			out = doc.domain()
			return nil
		}
		if doc.FailedAttempts >= 5 || !now.Before(doc.ExpiresAt) || claims.Subject != doc.AuthID || claims.ApplicationID != doc.ApplicationID || len(signatureDigest) != 32 {
			return domain.ErrFailed
		}
		if err = r.allowAccountWrite(tx, doc.AuthID, now); err != nil {
			return err
		}
		set := bson.M{"state": domain.Completed, "signaturedigest": bytes.Clone(signatureDigest), "jti": claims.JTI, "authtime": claims.AuthTime, "issuedat": claims.IssuedAt, "notbefore": claims.NotBefore, "proofexpiresat": claims.ExpiresAt, "purgeat": claims.ExpiresAt}
		result, err := r.auth.database.Collection(ApplicationCloseReauthOperationCollection).UpdateOne(tx, bson.M{"operationid": id, "state": domain.Pending, "failedattempts": doc.FailedAttempts}, bson.M{"$set": set})
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return domain.ErrFailed
		}
		if _, err = r.auth.database.Collection(ApplicationCloseReauthAuditCollection).InsertOne(tx, bson.M{"operationId": id, "authId": doc.AuthID, "credentialId": doc.CredentialID, "applicationId": app, "result": "COMPLETED", "jti": claims.JTI, "occurredAt": now}); err != nil {
			return err
		}
		doc.State = domain.Completed
		doc.SignatureDigest = bytes.Clone(signatureDigest)
		doc.JTI = claims.JTI
		doc.AuthTime = claims.AuthTime
		doc.IssuedAt = claims.IssuedAt
		doc.NotBefore = claims.NotBefore
		doc.ProofExpiresAt = claims.ExpiresAt
		doc.PurgeAt = claims.ExpiresAt
		out = doc.domain()
		return nil
	})
	return out, err
}

func (r *ApplicationCloseReauthRepository) Fail(ctx context.Context, id string, now time.Time) error {
	return r.semanticTx(ctx, func(tx context.Context) error {
		doc, err := r.read(tx, id)
		if err != nil {
			return err
		}
		if doc.State != domain.Pending || doc.FailedAttempts >= 5 || !now.Before(doc.ExpiresAt) {
			return domain.ErrFailed
		}
		if err = r.allowAccountWrite(tx, doc.AuthID, now); err != nil {
			return err
		}
		result, err := r.auth.database.Collection(ApplicationCloseReauthOperationCollection).UpdateOne(tx, bson.M{"operationid": id, "state": domain.Pending, "expiresat": bson.M{"$gt": now}, "failedattempts": doc.FailedAttempts}, bson.M{"$inc": bson.M{"failedattempts": int64(1)}})
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return domain.ErrFailed
		}
		_, err = r.auth.database.Collection(ApplicationCloseReauthAuditCollection).InsertOne(tx, bson.M{"operationId": id, "authId": doc.AuthID, "credentialId": doc.CredentialID, "applicationId": doc.ApplicationID, "result": "SIGNATURE_REJECTED", "attempt": doc.FailedAttempts + 1, "occurredAt": now})
		if err != nil {
			return err
		}
		return nil
	})
}
