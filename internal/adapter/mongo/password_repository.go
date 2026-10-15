package mongo

import (
	"bytes"
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	authport "iwut-auth-center/internal/authentication/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	"iwut-auth-center/internal/password/domain"
	"iwut-auth-center/internal/password/port"
)

const (
	PasswordCollection             = "auth_passwords"
	PasswordChangeCollection       = "auth_password_changes"
	PasswordAuditCollection        = "auth_password_audit"
	PasswordNotificationCollection = "auth_password_notifications"
)

type PasswordRepository struct {
	auth  *AuthenticationRepository
	keyID string
}

func NewPasswordRepository(auth *AuthenticationRepository, keyID string) (*PasswordRepository, error) {
	if auth == nil || len(keyID) != 64 {
		return nil, domain.ErrUnavailable
	}
	return &PasswordRepository{auth, keyID}, nil
}

type passwordDocument struct {
	AuthID               string    `bson:"authId"`
	Revision             int64     `bson:"passwordRevision"`
	Algorithm            string    `bson:"algorithm"`
	FormatVersion        int64     `bson:"formatVersion"`
	NormalizationVersion string    `bson:"normalizationVersion"`
	MemoryKiB            int64     `bson:"memoryKiB"`
	Iterations           int64     `bson:"iterations"`
	Parallelism          int64     `bson:"parallelism"`
	Salt                 []byte    `bson:"salt"`
	Hash                 []byte    `bson:"hash"`
	ChangedAt            time.Time `bson:"changedAt"`
}

func passwordDoc(r domain.Record) passwordDocument {
	m := r.Material
	return passwordDocument{r.AuthID, r.Revision, m.Algorithm, int64(m.FormatVersion), m.NormalizationVersion, int64(m.Parameters.MemoryKiB), int64(m.Parameters.Iterations), int64(m.Parameters.Parallelism), m.Salt, m.Hash, r.ChangedAt}
}

func decodePassword(raw bson.Raw) (domain.Record, error) {
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "passwordRevision": bson.TypeInt64, "algorithm": bson.TypeString, "formatVersion": bson.TypeInt64, "normalizationVersion": bson.TypeString, "memoryKiB": bson.TypeInt64, "iterations": bson.TypeInt64, "parallelism": bson.TypeInt64, "salt": bson.TypeBinary, "hash": bson.TypeBinary, "changedAt": bson.TypeDateTime}) {
		return domain.Record{}, domain.ErrUnavailable
	}
	var doc passwordDocument
	if bson.Unmarshal(raw, &doc) != nil || doc.MemoryKiB < 19456 || doc.MemoryKiB > 262144 || doc.Iterations < 2 || doc.Iterations > 6 || doc.Parallelism < 1 || doc.Parallelism > 4 || doc.FormatVersion != 1 {
		return domain.Record{}, domain.ErrUnavailable
	}
	record := domain.Record{AuthID: doc.AuthID, Revision: doc.Revision, ChangedAt: doc.ChangedAt, Material: domain.Material{Algorithm: doc.Algorithm, FormatVersion: int(doc.FormatVersion), NormalizationVersion: doc.NormalizationVersion, Parameters: domain.Parameters{MemoryKiB: uint32(doc.MemoryKiB), Iterations: uint32(doc.Iterations), Parallelism: uint8(doc.Parallelism)}, Salt: doc.Salt, Hash: doc.Hash}}
	if !record.Valid() {
		return domain.Record{}, domain.ErrUnavailable
	}
	return record, nil
}

func EnsurePasswordSchema(ctx context.Context, db *m.Database) error {
	if db == nil {
		return domain.ErrUnavailable
	}
	indexes := map[string][]m.IndexModel{
		PasswordCollection: {{Keys: bson.D{{Key: "authId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("password_owner_unique")}},
		PasswordChangeCollection: {
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("password_change_request_unique")},
			{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("password_change_operation_unique")},
			{Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("password_change_retention")},
		},
		PasswordAuditCollection: {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("password_audit_operation_unique")}},
		PasswordNotificationCollection: {
			{Keys: bson.D{{Key: "eventId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("password_notification_event_unique")},
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "state", Value: 1}, {Key: "nextAttemptAt", Value: 1}}, Options: options.Index().SetName("password_notification_owner_due")},
			{Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("password_notification_retention")},
		},
	}
	for col, models := range indexes {
		if _, err := db.Collection(col).Indexes().CreateMany(ctx, models); err != nil {
			return err
		}
	}
	return nil
}

// InitializePasswordTx is registration-only; missing records are not synthesized
// by readers. Caller owns the same USER/email/credential/Session transaction.
func (r *PasswordRepository) InitializePasswordTx(ctx context.Context, record domain.Record) error {
	if !record.Valid() || record.Revision != 1 {
		return domain.ErrUnavailable
	}
	_, err := r.auth.database.Collection(PasswordCollection).InsertOne(ctx, passwordDoc(record))
	return err
}

func (r *PasswordRepository) readPasswordTx(ctx context.Context, authID string) (domain.Record, error) {
	var raw bson.Raw
	err := r.auth.database.Collection(PasswordCollection).FindOne(ctx, bson.M{"authId": authID}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return domain.Record{}, domain.ErrUnavailable
	}
	if err != nil {
		return domain.Record{}, err
	}
	return decodePassword(raw)
}

func passwordSessionError(err error) error {
	if errors.Is(err, authport.ErrSessionInvalid) || errors.Is(err, authport.ErrAuthenticationFailed) {
		return domain.ErrSessionInvalid
	}
	return err
}

func (r *PasswordRepository) ReadSnapshot(ctx context.Context, digest []byte, now time.Time) (port.Snapshot, error) {
	var result port.Snapshot
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		session, err := r.auth.CheckSessionReadTx(tx, digest, now)
		if err != nil {
			return passwordSessionError(err)
		}
		record, err := r.readPasswordTx(tx, session.AuthID)
		if err != nil {
			return err
		}
		_, minimum, err := r.auth.CredentialBoundsTx(tx, session.AuthID)
		if err != nil {
			return err
		}
		result = port.Snapshot{Session: session, Password: record, MinimumCredentialRevision: minimum}
		return nil
	})
	return result, err
}

type passwordChangeDocument struct {
	AuthID               string    `bson:"authId"`
	RequestID            string    `bson:"requestId"`
	OperationID          string    `bson:"operationId"`
	SourceSessionID      string    `bson:"sourceSessionId"`
	RetainedCredentialID string    `bson:"retainedCredentialId"`
	KeyID                string    `bson:"keyId"`
	AccountRevision      int64     `bson:"originalAccountRevision"`
	PasswordRevision     int64     `bson:"originalPasswordRevision"`
	RequestMAC           []byte    `bson:"requestMac"`
	CreatedAt            time.Time `bson:"createdAt"`
	RetainUntil          time.Time `bson:"retainUntil"`
}

func changeDoc(o port.Change) passwordChangeDocument {
	return passwordChangeDocument{o.AuthID, o.RequestID, o.OperationID, o.SourceSessionID, o.RetainedCredentialID, o.KeyID, o.OriginalAccountRevision, o.OriginalPasswordRevision, o.RequestMAC, o.CreatedAt, o.RetainUntil}
}
func (o passwordChangeDocument) domain() port.Change {
	return port.Change{AuthID: o.AuthID, RequestID: o.RequestID, OperationID: o.OperationID, SourceSessionID: o.SourceSessionID, RetainedCredentialID: o.RetainedCredentialID, KeyID: o.KeyID, OriginalAccountRevision: o.AccountRevision, OriginalPasswordRevision: o.PasswordRevision, RequestMAC: o.RequestMAC, CreatedAt: o.CreatedAt, RetainUntil: o.RetainUntil}
}

func (r *PasswordRepository) changeTx(ctx context.Context, authID, requestID string, now time.Time) (port.Change, bool, error) {
	var raw bson.Raw
	err := r.auth.database.Collection(PasswordChangeCollection).FindOne(ctx, bson.M{"authId": authID, "requestId": requestID, "retainUntil": bson.M{"$gt": now}}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return port.Change{}, false, nil
	}
	if err != nil {
		return port.Change{}, false, err
	}
	if !identityFields(raw, map[string]bson.Type{"originalAccountRevision": bson.TypeInt64, "originalPasswordRevision": bson.TypeInt64}) {
		return port.Change{}, false, domain.ErrUnavailable
	}
	var doc passwordChangeDocument
	if bson.Unmarshal(raw, &doc) != nil || doc.AuthID != authID || doc.RequestID != requestID || !deviceprotocol.ValidID(doc.OperationID) || !deviceprotocol.ValidID(doc.SourceSessionID) || !deviceprotocol.ValidID(doc.RetainedCredentialID) || len(doc.KeyID) != 64 || len(doc.RequestMAC) != 32 || doc.AccountRevision <= 0 || doc.PasswordRevision <= 0 || doc.CreatedAt.IsZero() || !doc.RetainUntil.Equal(doc.CreatedAt.Add(24*time.Hour)) {
		return port.Change{}, false, domain.ErrUnavailable
	}
	return doc.domain(), true, nil
}

func (r *PasswordRepository) FindChange(ctx context.Context, digest []byte, requestID string, now time.Time) (port.Change, bool, error) {
	if !deviceprotocol.ValidID(requestID) {
		return port.Change{}, false, domain.ErrInvalidInput
	}
	var result port.Change
	var found bool
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		session, err := r.auth.CheckSessionReadTx(tx, digest, now)
		if err != nil {
			return passwordSessionError(err)
		}
		result, found, err = r.changeTx(tx, session.AuthID, requestID, r.auth.currentTime(now))
		return err
	})
	return result, found, err
}

func (r *PasswordRepository) CommitChange(ctx context.Context, c port.ChangeCommit, now time.Time) error {
	op := c.Operation
	before := c.Snapshot
	session := c.Session
	revision, passwordRevision, err := domain.NextRevisions(before.Session.AccountRevision, before.MinimumCredentialRevision, before.Password.Revision)
	if err != nil {
		return err
	}
	if !before.Password.Valid() || before.Password.AuthID != op.AuthID || !c.NewMaterial.Valid() || op.KeyID != r.keyID || op.AuthID != before.Session.AuthID || op.RequestID == "" || !deviceprotocol.ValidID(op.RequestID) || !deviceprotocol.ValidID(op.OperationID) || op.SourceSessionID != before.Session.SessionID || op.RetainedCredentialID != before.Session.CredentialID || op.OriginalAccountRevision != before.Session.AccountRevision || op.OriginalPasswordRevision != before.Password.Revision || len(op.RequestMAC) != 32 || !op.RetainUntil.Equal(op.CreatedAt.Add(24*time.Hour)) || session.AuthID != op.AuthID || session.CredentialID != op.RetainedCredentialID || session.SourceSessionID != op.SourceSessionID || session.SessionID == before.Session.SessionID || bytes.Equal(session.TokenDigest, before.Session.TokenDigest) || session.AccountRevision != revision || session.PasswordRevision != passwordRevision || session.AuthenticationMethod != domain.PasswordAndSession {
		return domain.ErrUnavailable
	}
	return r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		observed := r.auth.currentTime(now)
		caller, err := r.auth.CheckSessionReadTx(tx, before.Session.TokenDigest, observed)
		if err != nil {
			return passwordSessionError(err)
		}
		if caller.SessionID != before.Session.SessionID || caller.AuthID != op.AuthID || caller.CredentialID != op.RetainedCredentialID || caller.AccountRevision != before.Session.AccountRevision {
			return domain.ErrConflict
		}
		if _, found, err := r.changeTx(tx, op.AuthID, op.RequestID, observed); err != nil {
			return err
		} else if found {
			return domain.ErrAlreadyCompleted
		}
		// Pending exit coordination is never implicitly canceled by a password write.
		pending, err := r.auth.database.Collection(OwnerExitCollection).CountDocuments(tx, bson.M{"authId": op.AuthID, "decision": "PENDING"}, options.Count().SetLimit(1))
		if err != nil {
			return err
		}
		if pending > 0 {
			return domain.ErrConflict
		}
		if err := sharedOperationCapacityTx(tx, r.auth.database, observed, 10000, false); errors.Is(err, authport.ErrLimitExceeded) {
			return domain.ErrLimited
		} else if err != nil {
			return err
		}
		count, err := r.auth.database.Collection(PasswordNotificationCollection).CountDocuments(tx, bson.M{"retainUntil": bson.M{"$gt": observed}}, options.Count().SetLimit(1000000))
		if err != nil {
			return err
		}
		if count >= 1000000 {
			return domain.ErrLimited
		}
		record, err := r.readPasswordTx(tx, op.AuthID)
		if err != nil {
			return err
		}
		if record.Revision != before.Password.Revision {
			return domain.ErrConflict
		}
		_, minimum, err := r.auth.CredentialBoundsTx(tx, op.AuthID)
		if err != nil {
			return err
		}
		if minimum != before.MinimumCredentialRevision {
			return domain.ErrConflict
		}
		// Current binding is notification destination only; it does not authorize
		// the change. This baseline adapter is replaced by the accepted email-list
		// primary-role reader before public activation.
		binding, _, err := ReadPrimaryEmailTx(tx, r.auth.database, op.AuthID)
		if err != nil {
			return domain.ErrUnavailable
		}
		address, err := email.NormalizeEmail(binding.Email)
		if err != nil || address != binding.Email || binding.VerifiedAt.IsZero() {
			return domain.ErrUnavailable
		}
		updated, err := r.auth.database.Collection(PrincipalCollection).UpdateOne(tx, bson.M{"authId": op.AuthID, "accountStatus": "ACTIVE", "accountRevision": before.Session.AccountRevision, "minimumCredentialRevision": minimum}, bson.M{"$set": bson.M{"accountRevision": revision, "minimumCredentialRevision": revision, "updatedAt": observed}})
		if err != nil {
			return err
		}
		if updated.MatchedCount != 1 {
			return domain.ErrConflict
		}
		updated, err = r.auth.database.Collection(CredentialCollection).UpdateOne(tx, bson.M{"authId": op.AuthID, "credentialId": op.RetainedCredentialID, "revokedAt": nil, "credentialRevision": bson.M{"$gte": minimum, "$lte": before.Session.AccountRevision}}, bson.M{"$set": bson.M{"credentialRevision": revision}})
		if err != nil {
			return err
		}
		if updated.MatchedCount != 1 {
			return domain.ErrConflict
		}
		updated, err = r.auth.database.Collection(PasswordCollection).ReplaceOne(tx, bson.M{"authId": op.AuthID, "passwordRevision": record.Revision}, passwordDoc(domain.Record{AuthID: op.AuthID, Revision: passwordRevision, Material: c.NewMaterial, ChangedAt: observed}))
		if err != nil {
			return err
		}
		if updated.MatchedCount != 1 {
			return domain.ErrConflict
		}
		if err = r.auth.CreateSessionTx(tx, session, observed); err != nil {
			return err
		}
		if _, err = r.auth.database.Collection(PasswordChangeCollection).InsertOne(tx, changeDoc(op)); err != nil {
			return err
		}
		if _, err = r.auth.database.Collection(PasswordAuditCollection).InsertOne(tx, bson.M{"operationId": op.OperationID, "authId": op.AuthID, "action": "PASSWORD_CHANGED", "sourceSessionId": op.SourceSessionID, "retainedCredentialId": op.RetainedCredentialID, "accountRevision": revision, "passwordRevision": passwordRevision, "at": observed}); err != nil {
			return err
		}
		_, err = r.auth.database.Collection(PasswordNotificationCollection).InsertOne(tx, bson.M{"eventId": op.OperationID, "authId": op.AuthID, "kind": "PASSWORD_CHANGED", "email": address, "state": "PENDING", "attempts": int64(0), "createdAt": observed, "nextAttemptAt": observed, "retainUntil": observed.Add(24 * time.Hour)})
		return err
	})
}

// UpgradeHashCAS does not advance either authentication or password revisions.
// The exact previous hash/salt prevent a stale rehash from overwriting a peer.
func (r *PasswordRepository) UpgradeHashCAS(ctx context.Context, before domain.Record, material domain.Material) (bool, error) {
	if !before.Valid() || !material.Valid() || material.Parameters.MemoryKiB < before.Material.Parameters.MemoryKiB || material.Parameters.Iterations < before.Material.Parameters.Iterations {
		return false, domain.ErrUnavailable
	}
	var changed bool
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		if _, err := r.auth.AccountRevisionTx(tx, before.AuthID); err != nil {
			return err
		}
		replacement := before
		replacement.Material = material
		result, err := r.auth.database.Collection(PasswordCollection).ReplaceOne(tx, bson.M{"authId": before.AuthID, "passwordRevision": before.Revision, "hash": before.Material.Hash, "salt": before.Material.Salt}, passwordDoc(replacement))
		if err != nil {
			return err
		}
		changed = result.MatchedCount == 1
		return nil
	})
	return changed, err
}

var _ port.ChangeRepository = (*PasswordRepository)(nil)
