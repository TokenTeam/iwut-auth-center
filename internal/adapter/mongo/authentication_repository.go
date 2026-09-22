package mongo

import (
	"bytes"
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readconcern"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"

	"iwut-auth-center/internal/adapter/deviceprotocol"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
)

const (
	AuthenticationOperationCollection = "auth_authentication_operations"
	CredentialCollection              = "auth_credentials"
	SessionCollection                 = "auth_sessions"
	AuthenticationRuntimeCollection   = "auth_runtime"
)

type OperationDocument struct {
	OperationID           string    `bson:"operationId"`
	Purpose               string    `bson:"purpose"`
	ProtocolVersion       string    `bson:"protocolVersion"`
	ServiceID             string    `bson:"serviceId"`
	ApplicationID         string    `bson:"applicationId"`
	Challenge             []byte    `bson:"challenge"`
	ExpiresAt             time.Time `bson:"expiresAt"`
	CreatedAt             time.Time `bson:"createdAt"`
	LocatorKind           string    `bson:"locatorKind"`
	LocatorValue          []byte    `bson:"locatorValue"`
	CredentialID          string    `bson:"credentialId,omitempty"`
	AuthID                string    `bson:"authId,omitempty"`
	PublicKey             []byte    `bson:"publicKey,omitempty"`
	Acceptable            bool      `bson:"acceptable"`
	Status                string    `bson:"status"`
	FailedAttempts        int       `bson:"failedAttempts"`
	CompletedAuthID       string    `bson:"completedAuthId,omitempty"`
	CompletedCredentialID string    `bson:"completedCredentialId,omitempty"`
	CompletedSessionID    string    `bson:"completedSessionId,omitempty"`
	SchemeVersion         string    `bson:"schemeVersion,omitempty"`
	KeyVersion            string    `bson:"keyVersion,omitempty"`
	LookupKey             []byte    `bson:"lookupKey,omitempty"`
	Nonce                 []byte    `bson:"nonce,omitempty"`
	Ciphertext            []byte    `bson:"ciphertext,omitempty"`
}

type CredentialDocument struct {
	CredentialID    string     `bson:"credentialId"`
	AuthID          string     `bson:"authId"`
	ProtocolVersion string     `bson:"protocolVersion"`
	PublicKey       []byte     `bson:"publicKey"`
	Fingerprint     []byte     `bson:"fingerprint"`
	CreatedAt       time.Time  `bson:"createdAt"`
	RevokedAt       *time.Time `bson:"revokedAt,omitempty"`
}

type SessionDocument struct {
	SessionID            string     `bson:"sessionId"`
	AuthID               string     `bson:"authId"`
	AuthenticationMethod string     `bson:"authenticationMethod"`
	CredentialID         string     `bson:"credentialId"`
	TokenDigest          []byte     `bson:"tokenDigest"`
	AuthenticatedAt      time.Time  `bson:"authenticatedAt"`
	CreatedAt            time.Time  `bson:"createdAt"`
	LastUsedAt           time.Time  `bson:"lastUsedAt"`
	ExpiresAt            time.Time  `bson:"expiresAt"`
	RevokedAt            *time.Time `bson:"revokedAt,omitempty"`
}

type AuthenticationRepository struct {
	database                *drivermongo.Database
	maxPending, maxFailures int
	clock                   func() time.Time
}

func NewAuthenticationRepository(database *drivermongo.Database, maxPending, maxFailures int) (*AuthenticationRepository, error) {
	if database == nil || maxPending <= 0 || maxFailures <= 0 {
		return nil, port.ErrUnavailable
	}
	return &AuthenticationRepository{database: database, maxPending: maxPending, maxFailures: maxFailures, clock: time.Now}, nil
}

func EnsureAuthenticationSchema(ctx context.Context, db *drivermongo.Database) error {
	if db == nil {
		return port.ErrUnavailable
	}
	indexes := map[string][]drivermongo.IndexModel{
		AuthenticationOperationCollection: {
			{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("operation_id_unique")},
			{Keys: bson.D{{Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}, Options: options.Index().SetName("operation_pending_expiry")},
		},
		CredentialCollection: {
			{Keys: bson.D{{Key: "credentialId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("credential_id_unique")},
			{Keys: bson.D{{Key: "fingerprint", Value: 1}}, Options: options.Index().SetUnique(true).SetName("credential_fingerprint_unique")},
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "revokedAt", Value: 1}}, Options: options.Index().SetName("credential_owner_active")},
		},
		SessionCollection: {
			{Keys: bson.D{{Key: "sessionId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("session_id_unique")},
			{Keys: bson.D{{Key: "tokenDigest", Value: 1}}, Options: options.Index().SetUnique(true).SetName("session_digest_unique")},
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "revokedAt", Value: 1}, {Key: "lastUsedAt", Value: 1}, {Key: "createdAt", Value: 1}, {Key: "sessionId", Value: 1}}, Options: options.Index().SetName("session_owner_lru")},
			{Keys: bson.D{{Key: "credentialId", Value: 1}}, Options: options.Index().SetName("session_credential")},
		},
	}
	for collection, models := range indexes {
		if _, err := db.Collection(collection).Indexes().CreateMany(ctx, models); err != nil {
			return port.ErrUnavailable
		}
	}
	_, err := db.Collection(AuthenticationRuntimeCollection).UpdateOne(ctx, bson.M{"_id": "authentication"}, bson.M{"$setOnInsert": bson.M{"fence": int64(0)}}, options.UpdateOne().SetUpsert(true))
	if err != nil {
		return port.ErrUnavailable
	}
	return nil
}

// WithAuthTransaction serializes auth mutations, exact LRU and checks at a durable
// database fence. Snapshot + majority ensures a check started after a committed
// revocation cannot read an older state. All callbacks may run more than once.
// Future principal disable and credential mutation must also use this boundary;
// participating records are additionally touched to conflict with direct writers.
func (r *AuthenticationRepository) WithAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	session, err := r.database.Client().StartSession()
	if err != nil {
		return port.ErrUnavailable
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(ctx, func(tx context.Context) (any, error) {
		result, err := r.database.Collection(AuthenticationRuntimeCollection).UpdateOne(tx, bson.M{"_id": "authentication"}, bson.M{"$inc": bson.M{"fence": int64(1)}})
		if err != nil {
			return nil, err
		}
		if result.MatchedCount != 1 {
			return nil, port.ErrUnavailable
		}
		return nil, fn(tx)
	}, options.Transaction().SetReadConcern(readconcern.Snapshot()).SetWriteConcern(writeconcern.Majority()).SetReadPreference(readpref.Primary()))
	if err != nil {
		for _, known := range []error{port.ErrCredentialRegistered, port.ErrAuthenticationFailed, port.ErrSessionInvalid, port.ErrAlreadyCompleted, port.ErrLimitExceeded, port.ErrNotFound} {
			if errors.Is(err, known) {
				return known
			}
		}
		return port.ErrUnavailable
	}
	return nil
}

func (r *AuthenticationRepository) CreateOperation(ctx context.Context, op domain.Operation, now time.Time) error {
	return r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		if op.Status != domain.Pending || op.FailedAttempts != 0 || !now.Before(op.ExpiresAt) {
			return port.ErrAuthenticationFailed
		}
		// Expiration releases capacity without relying on TTL; encrypted registration
		// snapshots are cleared in the same transition, never copied into history.
		_, err := r.database.Collection(AuthenticationOperationCollection).UpdateMany(tx, bson.M{"status": domain.Pending, "expiresAt": bson.M{"$lte": now}}, bson.M{"$set": bson.M{"status": domain.Closed}, "$unset": associationUnset()})
		if err != nil {
			return err
		}
		count, err := r.database.Collection(AuthenticationOperationCollection).CountDocuments(tx, bson.M{"status": domain.Pending, "expiresAt": bson.M{"$gt": now}})
		if err != nil {
			return err
		}
		if count >= int64(r.maxPending) {
			return port.ErrLimitExceeded
		}
		_, err = r.database.Collection(AuthenticationOperationCollection).InsertOne(tx, operationDocument(op))
		return err
	})
}

func (r *AuthenticationRepository) GetOperation(ctx context.Context, id string) (domain.Operation, error) {
	var doc OperationDocument
	err := r.database.Collection(AuthenticationOperationCollection).FindOne(ctx, bson.M{"operationId": id}).Decode(&doc)
	if errors.Is(err, drivermongo.ErrNoDocuments) {
		return domain.Operation{}, port.ErrNotFound
	}
	if err != nil {
		return domain.Operation{}, port.ErrUnavailable
	}
	return doc.Domain(), nil
}

func (r *AuthenticationRepository) RecordFailure(ctx context.Context, id string, now time.Time) error {
	return r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		op, err := r.GetOperation(tx, id)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if op.Status != domain.Pending {
			return nil
		}
		update := bson.M{"$inc": bson.M{"failedAttempts": 1}}
		if op.FailedAttempts+1 >= r.maxFailures || !now.Before(op.ExpiresAt) {
			update["$set"] = bson.M{"status": domain.Closed}
			update["$unset"] = associationUnset()
		}
		_, err = r.database.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": id, "status": domain.Pending}, update)
		return err
	})
}

func (r *AuthenticationRepository) ResolveCredential(ctx context.Context, locator domain.Locator) (domain.Credential, bool, error) {
	var credential domain.Credential
	acceptable := false
	err := r.WithAuthTransaction(ctx, func(tx context.Context) error {
		filter := bson.M{"revokedAt": nil, "protocolVersion": domain.ProtocolVersion}
		switch locator.Kind {
		case domain.CredentialIDLocator:
			filter["credentialId"] = string(locator.Value)
		case domain.FingerprintLocator:
			filter["fingerprint"] = locator.Value
		default:
			return port.ErrAuthenticationFailed
		}
		var doc CredentialDocument
		if err := r.database.Collection(CredentialCollection).FindOne(tx, filter).Decode(&doc); errors.Is(err, drivermongo.ErrNoDocuments) {
			return nil
		} else if err != nil {
			return err
		}
		if !validCredential(doc) {
			return nil
		}
		count, err := r.database.Collection(PrincipalCollection).CountDocuments(tx, bson.M{"authId": doc.AuthID, "principalType": "USER", "accountStatus": "ACTIVE"})
		if err != nil {
			return err
		}
		if count == 1 {
			credential = doc.Domain()
			acceptable = true
		}
		return nil
	})
	return credential, acceptable, err
}

func (r *AuthenticationRepository) ConsumeOperationTx(ctx context.Context, id, purpose, authID, credentialID, sessionID string, now time.Time) error {
	now = r.currentTime(now)
	op, err := r.GetOperation(ctx, id)
	if err != nil {
		return err
	}
	if op.Purpose != purpose {
		return port.ErrAuthenticationFailed
	}
	if op.Status == domain.Completed {
		return port.ErrAlreadyCompleted
	}
	if op.Status != domain.Pending || !now.Before(op.ExpiresAt) || op.FailedAttempts < 0 || op.FailedAttempts >= r.maxFailures {
		return port.ErrAuthenticationFailed
	}
	result, err := r.database.Collection(AuthenticationOperationCollection).UpdateOne(ctx, bson.M{"operationId": id, "purpose": purpose, "status": domain.Pending, "expiresAt": bson.M{"$gt": now}, "failedAttempts": bson.M{"$lt": r.maxFailures}}, bson.M{"$set": bson.M{"status": domain.Completed, "completedAuthId": authID, "completedCredentialId": credentialID, "completedSessionId": sessionID}, "$unset": associationUnset()})
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return port.ErrAuthenticationFailed
	}
	return nil
}

func (r *AuthenticationRepository) InsertCredentialTx(ctx context.Context, credential domain.Credential) error {
	_, err := r.database.Collection(CredentialCollection).InsertOne(ctx, credentialDocument(credential))
	return err
}

func (r *AuthenticationRepository) ConfirmPrincipalCredentialTx(ctx context.Context, authID, credentialID string, now time.Time) error {
	result, err := r.database.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": authID, "principalType": "USER", "accountStatus": "ACTIVE"}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}})
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return port.ErrAuthenticationFailed
	}
	result, err = r.database.Collection(CredentialCollection).UpdateOne(ctx, bson.M{"credentialId": credentialID, "authId": authID, "revokedAt": nil, "protocolVersion": domain.ProtocolVersion}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}})
	if err != nil {
		return err
	}
	if result.MatchedCount != 1 {
		return port.ErrAuthenticationFailed
	}
	return nil
}

func (r *AuthenticationRepository) CompleteLogin(ctx context.Context, expected domain.Operation, session domain.Session, now time.Time) error {
	err := r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		op, err := r.GetOperation(tx, expected.OperationID)
		if err != nil {
			return err
		}
		if op.Purpose != domain.Login {
			return port.ErrAuthenticationFailed
		}
		if op.Status == domain.Completed {
			return port.ErrAlreadyCompleted
		}
		if !op.Acceptable || op.AuthID != session.AuthID || op.CredentialID != session.CredentialID || !bytes.Equal(op.PublicKey, expected.PublicKey) {
			return port.ErrAuthenticationFailed
		}
		var credential CredentialDocument
		if err := r.database.Collection(CredentialCollection).FindOne(tx, bson.M{"credentialId": op.CredentialID}).Decode(&credential); errors.Is(err, drivermongo.ErrNoDocuments) {
			return port.ErrAuthenticationFailed
		} else if err != nil {
			return err
		}
		if !validCredential(credential) || !bytes.Equal(credential.PublicKey, op.PublicKey) {
			return port.ErrAuthenticationFailed
		}
		if err := r.ConfirmPrincipalCredentialTx(tx, op.AuthID, op.CredentialID, now); err != nil {
			return err
		}
		if err := r.ConsumeOperationTx(tx, op.OperationID, domain.Login, session.AuthID, session.CredentialID, session.SessionID, now); err != nil {
			return err
		}
		return r.CreateSessionTx(tx, session, now)
	})
	if errors.Is(err, port.ErrAuthenticationFailed) {
		if failureErr := r.RecordFailure(ctx, expected.OperationID, now); failureErr != nil {
			return failureErr
		}
	}
	return err
}

// CreateSessionTx is called within WithAuthTransaction after ownership and proof
// confirmation; its candidate ID and secret digest are fixed outside retries.
func (r *AuthenticationRepository) CreateSessionTx(ctx context.Context, session domain.Session, now time.Time) error {
	now = r.currentTime(now)
	if !validSession(sessionDocument(session)) || !now.Before(session.ExpiresAt) {
		return port.ErrUnavailable
	}
	if err := r.ConfirmPrincipalCredentialTx(ctx, session.AuthID, session.CredentialID, now); err != nil {
		return err
	}
	credentials, err := r.database.Collection(CredentialCollection).Find(ctx, bson.M{"authId": session.AuthID, "revokedAt": nil, "protocolVersion": domain.ProtocolVersion})
	if err != nil {
		return err
	}
	defer credentials.Close(ctx)
	ids := []string{}
	for credentials.Next(ctx) {
		var doc CredentialDocument
		if err := credentials.Decode(&doc); err != nil {
			return err
		}
		if validCredential(doc) {
			ids = append(ids, doc.CredentialID)
		}
	}
	if err := credentials.Err(); err != nil {
		return err
	}
	cursor, err := r.database.Collection(SessionCollection).Find(ctx, bson.M{"authId": session.AuthID, "revokedAt": nil, "expiresAt": bson.M{"$gt": now}, "credentialId": bson.M{"$in": ids}, "authenticationMethod": "DEVICE_CREDENTIAL"}, options.Find().SetSort(bson.D{{Key: "lastUsedAt", Value: 1}, {Key: "createdAt", Value: 1}, {Key: "sessionId", Value: 1}}))
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)
	candidates := []string{}
	for cursor.Next(ctx) {
		var doc SessionDocument
		if err := cursor.Decode(&doc); err != nil {
			return err
		}
		if validSession(doc) {
			candidates = append(candidates, doc.SessionID)
		}
	}
	if err := cursor.Err(); err != nil {
		return err
	}
	count := len(candidates) + 1 - 10
	if count > 0 {
		if _, err := r.database.Collection(SessionCollection).UpdateMany(ctx, bson.M{"sessionId": bson.M{"$in": candidates[:count]}, "revokedAt": nil}, bson.M{"$set": bson.M{"revokedAt": now}}); err != nil {
			return err
		}
	}
	_, err = r.database.Collection(SessionCollection).InsertOne(ctx, sessionDocument(session))
	return err
}

func (r *AuthenticationRepository) CheckSession(ctx context.Context, digest []byte, now time.Time) (domain.Session, error) {
	if len(digest) != 32 {
		return domain.Session{}, port.ErrSessionInvalid
	}
	var result domain.Session
	err := r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		var doc SessionDocument
		err := r.database.Collection(SessionCollection).FindOne(tx, bson.M{"tokenDigest": digest, "revokedAt": nil, "expiresAt": bson.M{"$gt": now}}).Decode(&doc)
		if errors.Is(err, drivermongo.ErrNoDocuments) {
			return port.ErrSessionInvalid
		}
		if err != nil {
			return err
		}
		if !validSession(doc) {
			return port.ErrSessionInvalid
		}
		var credential CredentialDocument
		err = r.database.Collection(CredentialCollection).FindOne(tx, bson.M{"credentialId": doc.CredentialID, "authId": doc.AuthID, "revokedAt": nil}).Decode(&credential)
		if errors.Is(err, drivermongo.ErrNoDocuments) {
			return port.ErrSessionInvalid
		}
		if err != nil {
			return err
		}
		if !validCredential(credential) {
			return port.ErrSessionInvalid
		}
		if err := r.ConfirmPrincipalCredentialTx(tx, doc.AuthID, doc.CredentialID, now); errors.Is(err, port.ErrAuthenticationFailed) {
			return port.ErrSessionInvalid
		} else if err != nil {
			return err
		}
		updated, err := r.database.Collection(SessionCollection).UpdateOne(tx, bson.M{"sessionId": doc.SessionID, "revokedAt": nil, "expiresAt": bson.M{"$gt": now}}, bson.M{"$max": bson.M{"lastUsedAt": now}})
		if err != nil {
			return err
		}
		if updated.MatchedCount != 1 {
			return port.ErrSessionInvalid
		}
		if now.After(doc.LastUsedAt) {
			doc.LastUsedAt = now
		}
		result = doc.Domain()
		return nil
	})
	return result, err
}

func associationUnset() bson.M { return bson.M{"lookupKey": "", "nonce": "", "ciphertext": ""} }
func (r *AuthenticationRepository) currentTime(floor time.Time) time.Time {
	now := r.clock().UTC().Truncate(time.Millisecond)
	if now.Before(floor) {
		return floor
	}
	return now
}

func validCredential(doc CredentialDocument) bool {
	protocol, _ := deviceprotocol.New("storage-validation")
	fingerprint, err := protocol.Fingerprint(doc.PublicKey)
	return err == nil && bytes.Equal(fingerprint, doc.Fingerprint) && deviceprotocol.ValidID(doc.CredentialID) && doc.AuthID != "" && doc.ProtocolVersion == domain.ProtocolVersion && !doc.CreatedAt.IsZero() && doc.RevokedAt == nil
}
func validSession(doc SessionDocument) bool {
	return deviceprotocol.ValidID(doc.SessionID) && doc.AuthID != "" && deviceprotocol.ValidID(doc.CredentialID) && doc.AuthenticationMethod == "DEVICE_CREDENTIAL" && len(doc.TokenDigest) == 32 && !doc.CreatedAt.IsZero() && !doc.AuthenticatedAt.IsZero() && !doc.LastUsedAt.Before(doc.CreatedAt) && doc.ExpiresAt.After(doc.CreatedAt) && doc.RevokedAt == nil
}

var _ port.LoginRepository = (*AuthenticationRepository)(nil)
