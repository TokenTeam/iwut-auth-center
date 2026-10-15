package mongo

import (
	"bytes"
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/credentialprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	pwd "iwut-auth-center/internal/password/domain"
	"math"
	"time"
)

const CredentialManagementOperationCollection = "auth_credential_management_operations"
const CredentialManagementAuditCollection = "auth_credential_management_audit_events"

type credentialManagementOperationDocument struct {
	OperationID        string     `bson:"operationId"`
	RequestID          string     `bson:"requestId"`
	Purpose            string     `bson:"purpose"`
	ServiceID          string     `bson:"serviceId"`
	ApplicationID      string     `bson:"applicationId"`
	AuthID             string     `bson:"authId"`
	SessionID          string     `bson:"sessionId"`
	CallerCredentialID string     `bson:"callerCredentialId"`
	TargetCredentialID string     `bson:"targetCredentialId"`
	AccountRevision    int64      `bson:"accountRevision"`
	PasswordRevision   int64      `bson:"passwordRevision"`
	FailedAttempts     int64      `bson:"failedAttempts"`
	PublicKey          []byte     `bson:"publicKey"`
	Challenge          []byte     `bson:"challenge"`
	CreatedAt          time.Time  `bson:"createdAt"`
	ExpiresAt          time.Time  `bson:"expiresAt"`
	RetainUntil        time.Time  `bson:"retainUntil"`
	Status             string     `bson:"status"`
	CompletedAt        *time.Time `bson:"completedAt,omitempty"`
}
type CredentialManagementRepository struct {
	auth      *AuthenticationRepository
	protocol  *credentialprotocol.Protocol
	serviceID string
}

func NewCredentialManagementRepository(a *AuthenticationRepository, serviceID string) (*CredentialManagementRepository, error) {
	p, err := credentialprotocol.New(serviceID)
	if err != nil || a == nil {
		return nil, d.ErrUnavailable
	}
	return &CredentialManagementRepository{a, p, serviceID}, nil
}
func EnsureCredentialManagementSchema(ctx context.Context, db *m.Database) error {
	for name, indexes := range map[string][]m.IndexModel{
		CredentialCollection: {{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "createdAt", Value: -1}, {Key: "credentialId", Value: -1}}, Options: options.Index().SetName("credential_owner_created_id")}},
		CredentialManagementOperationCollection: {
			{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}},
			{Keys: bson.D{{Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}},
			{Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
		},
		CredentialManagementAuditCollection: {
			{Keys: bson.D{{Key: "eventId", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "actorAuthId", Value: 1}, {Key: "occurredAt", Value: 1}}},
		},
	} {
		if _, err := db.Collection(name).Indexes().CreateMany(ctx, indexes); err != nil {
			return err
		}
	}
	return nil
}
func (r *CredentialManagementRepository) tx(ctx context.Context, fn func(context.Context) error) error {
	var semantic error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error { semantic = fn(tx); return semantic })
	if err == nil {
		return nil
	}
	for _, known := range d.Errors {
		if errors.Is(semantic, known) {
			return known
		}
	}
	return d.ErrUnavailable
}
func (r *CredentialManagementRepository) caller(ctx context.Context, digest []byte, now time.Time) (auth.Session, error) {
	s, err := r.auth.CheckSessionReadTx(ctx, digest, now)
	if errors.Is(err, ap.ErrSessionInvalid) {
		return s, d.ErrSession
	}
	return s, err
}
func (r *CredentialManagementRepository) Authenticate(ctx context.Context, digest []byte, now time.Time) (d.Caller, error) {
	var out d.Caller
	err := r.tx(ctx, func(tx context.Context) error {
		s, err := r.caller(tx, digest, r.auth.currentTime(now))
		if err != nil {
			return err
		}
		out = d.Caller{AuthID: s.AuthID, SessionID: s.SessionID, CredentialID: s.CredentialID, AccountRevision: s.AccountRevision}
		return nil
	})
	return out, err
}
func (r *CredentialManagementRepository) credential(ctx context.Context, owner, id string) (CredentialDocument, error) {
	var c CredentialDocument
	err := r.auth.database.Collection(CredentialCollection).FindOne(ctx, bson.M{"authId": owner, "credentialId": id}).Decode(&c)
	if errors.Is(err, m.ErrNoDocuments) {
		return c, d.ErrNotFound
	}
	if err != nil {
		return c, err
	}
	valid := c
	valid.RevokedAt = nil
	if !validCredential(valid) {
		return c, d.ErrUnavailable
	}
	return c, nil
}
func (r *CredentialManagementRepository) List(ctx context.Context, digest []byte, size int, cursor string, now time.Time) (d.Page, error) {
	var out d.Page
	err := r.tx(ctx, func(tx context.Context) error {
		observed := r.auth.currentTime(now)
		s, err := r.caller(tx, digest, observed)
		if err != nil {
			return err
		}
		_, minimum, err := r.auth.CredentialBoundsTx(tx, s.AuthID)
		if err != nil {
			return err
		}
		out = d.Page{CurrentCredentialID: s.CredentialID, ObservedAt: observed, Credentials: []d.Summary{}}
		filter := bson.M{"authId": s.AuthID}
		if cursor != "" {
			var raw bson.Raw
			err := r.auth.database.Collection(CredentialCollection).FindOne(tx, bson.M{"authId": s.AuthID, "credentialId": cursor}).Decode(&raw)
			if errors.Is(err, m.ErrNoDocuments) {
				return d.ErrCursor
			}
			if err != nil {
				return err
			}
			if !identityFields(raw, map[string]bson.Type{"createdAt": bson.TypeDateTime}) || raw.Lookup("createdAt").Time().IsZero() {
				return d.ErrUnavailable
			}
			stamp := raw.Lookup("createdAt").Time()
			filter["$or"] = bson.A{bson.M{"createdAt": bson.M{"$lt": stamp}}, bson.M{"createdAt": stamp, "credentialId": bson.M{"$lt": cursor}}}
		}
		cur, err := r.auth.database.Collection(CredentialCollection).Find(tx, filter, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}, {Key: "credentialId", Value: -1}}).SetLimit(201))
		if err != nil {
			return err
		}
		defer cur.Close(tx)
		var rows []bson.Raw
		if err = cur.All(tx, &rows); err != nil {
			return err
		}
		for i, raw := range rows {
			if i == 200 {
				break
			}
			var c CredentialDocument
			if bson.Unmarshal(raw, &c) != nil {
				return d.ErrUnavailable
			}
			v := c
			v.RevokedAt = nil
			if !validCredential(v) || c.CredentialRevision > s.AccountRevision {
				return d.ErrUnavailable
			}
			if c.RevokedAt == nil && pwd.EligibleCredential(c.CredentialRevision, minimum, s.AccountRevision) {
				out.Credentials = append(out.Credentials, d.Summary{CredentialID: c.CredentialID, Label: c.Label, LabelRevision: c.LabelRevision, CreatedAt: c.CreatedAt, IsCurrent: c.CredentialID == s.CredentialID})
			}
			if len(out.Credentials) == size || i == 199 {
				if i+1 < len(rows) {
					out.NextCursor = c.CredentialID
				}
				break
			}
		}
		return nil
	})
	return out, err
}
func (r *CredentialManagementRepository) audit(ctx context.Context, event, action string, s auth.Session, target string, revision int64, now time.Time) error {
	_, err := r.auth.database.Collection(CredentialManagementAuditCollection).InsertOne(ctx, bson.M{"eventId": event, "action": action, "actorAuthId": s.AuthID, "actorSessionId": s.SessionID, "callerCredentialId": s.CredentialID, "targetCredentialId": target, "labelRevision": revision, "occurredAt": now})
	return err
}
func (r *CredentialManagementRepository) SetLabel(ctx context.Context, digest []byte, id, label string, revision int64, event string, now time.Time) (d.LabelResult, error) {
	canonical, err := d.Label(label)
	if err != nil || canonical != label || revision < 0 || !d.ValidID(id) || !d.ValidID(event) {
		return d.LabelResult{}, d.ErrInvalid
	}
	var out d.LabelResult
	err = r.tx(ctx, func(tx context.Context) error {
		now = r.auth.currentTime(now)
		s, err := r.caller(tx, digest, now)
		if err != nil {
			return err
		}
		c, err := r.credential(tx, s.AuthID, id)
		if err != nil {
			return err
		}
		if c.RevokedAt != nil {
			return d.ErrNotFound
		}
		if c.LabelRevision != revision {
			return d.ErrLabelConflict
		}
		out = d.LabelResult{CredentialID: id, Label: c.Label, Revision: c.LabelRevision}
		if label == c.Label {
			return nil
		}
		if revision == math.MaxInt64 {
			return d.ErrUnavailable
		}
		filter := bson.M{"authId": s.AuthID, "credentialId": id, "revokedAt": nil, "labelRevision": revision}
		if revision == 0 {
			delete(filter, "labelRevision")
			filter["$or"] = bson.A{bson.M{"labelRevision": int64(0)}, bson.M{"labelRevision": bson.M{"$exists": false}, "label": bson.M{"$exists": false}}}
		}
		result, err := r.auth.database.Collection(CredentialCollection).UpdateOne(tx, filter, bson.M{"$set": bson.M{"label": label, "labelRevision": revision + 1}})
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return d.ErrNotFound
		}
		if err = r.audit(tx, event, "SET_LABEL", s, id, revision+1, now); err != nil {
			return err
		}
		out = d.LabelResult{CredentialID: id, Label: label, Revision: revision + 1}
		return nil
	})
	return out, err
}
func (r *CredentialManagementRepository) read(ctx context.Context, filter bson.M) (d.Operation, error) {
	raw, err := r.auth.database.Collection(CredentialManagementOperationCollection).FindOne(ctx, filter).Raw()
	if err != nil {
		return d.Operation{}, err
	}
	fields := map[string]bson.Type{}
	for _, key := range []string{"operationId", "requestId", "purpose", "serviceId", "applicationId", "authId", "sessionId", "callerCredentialId", "targetCredentialId", "status"} {
		fields[key] = bson.TypeString
	}
	for _, key := range []string{"accountRevision", "passwordRevision", "failedAttempts"} {
		fields[key] = bson.TypeInt64
	}
	for _, key := range []string{"createdAt", "expiresAt", "retainUntil"} {
		fields[key] = bson.TypeDateTime
	}
	fields["challenge"] = bson.TypeBinary
	fields["publicKey"] = bson.TypeBinary
	if completed := raw.Lookup("completedAt"); completed.Type != 0 && completed.Type != bson.TypeDateTime {
		return d.Operation{}, d.ErrUnavailable
	}
	var doc credentialManagementOperationDocument
	if !identityFields(raw, fields) || bson.Unmarshal(raw, &doc) != nil {
		return d.Operation{}, d.ErrUnavailable
	}
	op := d.Operation(doc)
	if !d.ValidID(op.RequestID) || op.AuthID == "" || op.AccountRevision < 1 || op.PasswordRevision < 1 || op.FailedAttempts < 0 || op.FailedAttempts > 5 || op.CallerCredentialID == op.TargetCredentialID || op.CreatedAt.IsZero() || !op.ExpiresAt.Equal(op.CreatedAt.Add(5*time.Minute)) || !op.RetainUntil.Equal(op.CreatedAt.Add(24*time.Hour)) {
		return op, d.ErrUnavailable
	}
	if _, err = r.protocol.SigningPayload(op); err != nil {
		return op, d.ErrUnavailable
	}
	if _, err = r.protocol.Fingerprint(op.PublicKey); err != nil {
		return op, d.ErrUnavailable
	}
	switch op.Status {
	case d.Pending:
		if op.FailedAttempts >= 5 || op.CompletedAt != nil {
			return op, d.ErrUnavailable
		}
	case d.Failed:
		if op.FailedAttempts != 5 || op.CompletedAt != nil {
			return op, d.ErrUnavailable
		}
	case d.Completed:
		if op.FailedAttempts >= 5 || op.CompletedAt == nil || op.CompletedAt.Before(op.CreatedAt) || !op.CompletedAt.Before(op.ExpiresAt) {
			return op, d.ErrUnavailable
		}
	default:
		return op, d.ErrUnavailable
	}
	return op, nil
}
func (r *CredentialManagementRepository) Begin(ctx context.Context, digest []byte, candidate d.Operation, now time.Time) (d.Operation, error) {
	var out d.Operation
	err := r.tx(ctx, func(tx context.Context) error {
		now = r.auth.currentTime(now)
		s, err := r.caller(tx, digest, now)
		if err != nil {
			return err
		}
		if candidate.TargetCredentialID == s.CredentialID {
			return d.ErrCurrent
		}
		if _, err = r.credential(tx, s.AuthID, candidate.TargetCredentialID); err != nil {
			return err
		}
		password, err := (&PasswordRepository{auth: r.auth}).readPasswordTx(tx, s.AuthID)
		if err != nil {
			return d.ErrUnavailable
		}
		prior, err := r.read(tx, bson.M{"authId": s.AuthID, "requestId": candidate.RequestID})
		if err == nil {
			if prior.SessionID != s.SessionID || prior.CallerCredentialID != s.CredentialID || prior.TargetCredentialID != candidate.TargetCredentialID || prior.AccountRevision != s.AccountRevision || prior.PasswordRevision != password.Revision || prior.ServiceID != r.serviceID || prior.ApplicationID != candidate.ApplicationID {
				return d.ErrConflict
			}
			if !now.Before(prior.RetainUntil) || prior.Status == d.Failed {
				return d.ErrProof
			}
			if prior.Status == d.Completed {
				return d.ErrCompleted
			}
			if !now.Before(prior.ExpiresAt) {
				return d.ErrProof
			}
			out = prior
			return nil
		}
		if !errors.Is(err, m.ErrNoDocuments) {
			return err
		}
		count, err := r.auth.database.Collection(CredentialManagementOperationCollection).CountDocuments(tx, bson.M{"authId": s.AuthID, "status": d.Pending, "expiresAt": bson.M{"$gt": now}}, options.Count().SetLimit(5))
		if err != nil {
			return err
		}
		if count >= 5 {
			return d.ErrRate
		}
		if err = sharedOperationCapacityTx(tx, r.auth.database, now, 10000, true); errors.Is(err, ap.ErrLimitExceeded) {
			return d.ErrRate
		} else if err != nil {
			return err
		}
		c, err := r.credential(tx, s.AuthID, s.CredentialID)
		if err != nil {
			return err
		}
		out = candidate
		out.AuthID = s.AuthID
		out.SessionID = s.SessionID
		out.CallerCredentialID = s.CredentialID
		out.PublicKey = bytes.Clone(c.PublicKey)
		out.AccountRevision = s.AccountRevision
		out.PasswordRevision = password.Revision
		if out.ServiceID != r.serviceID || !now.Before(out.ExpiresAt) {
			return d.ErrProof
		}
		_, err = r.auth.database.Collection(CredentialManagementOperationCollection).InsertOne(tx, credentialManagementOperationDocument(out))
		return err
	})
	return out, err
}
func (r *CredentialManagementRepository) bound(ctx context.Context, digest []byte, id string, now time.Time) (auth.Session, d.Operation, error) {
	s, err := r.caller(ctx, digest, now)
	if err != nil {
		return s, d.Operation{}, err
	}
	op, err := r.read(ctx, bson.M{"operationId": id, "authId": s.AuthID, "sessionId": s.SessionID, "callerCredentialId": s.CredentialID})
	if errors.Is(err, m.ErrNoDocuments) {
		return s, op, d.ErrProof
	}
	if err != nil {
		return s, op, err
	}
	if op.AuthID != s.AuthID || op.SessionID != s.SessionID || op.CallerCredentialID != s.CredentialID || op.AccountRevision != s.AccountRevision || op.ServiceID != r.serviceID || !now.Before(op.RetainUntil) || op.Status == d.Failed || op.Status == d.Pending && !now.Before(op.ExpiresAt) {
		return s, op, d.ErrProof
	}
	c, err := r.credential(ctx, s.AuthID, s.CredentialID)
	if err != nil {
		return s, op, err
	}
	if !bytes.Equal(c.PublicKey, op.PublicKey) {
		return s, op, d.ErrProof
	}
	password, err := (&PasswordRepository{auth: r.auth}).readPasswordTx(ctx, s.AuthID)
	if err != nil {
		return s, op, d.ErrUnavailable
	}
	if password.Revision != op.PasswordRevision {
		return s, op, d.ErrProof
	}
	return s, op, nil
}
func (r *CredentialManagementRepository) ReadForComplete(ctx context.Context, digest []byte, id string, now time.Time) (d.Operation, error) {
	var out d.Operation
	err := r.tx(ctx, func(tx context.Context) error {
		_, op, err := r.bound(tx, digest, id, r.auth.currentTime(now))
		out = op
		return err
	})
	return out, err
}
func (r *CredentialManagementRepository) Fail(ctx context.Context, digest []byte, id string, now time.Time) error {
	return r.tx(ctx, func(tx context.Context) error {
		_, op, err := r.bound(tx, digest, id, r.auth.currentTime(now))
		if err != nil {
			return err
		}
		if op.Status != d.Pending {
			return d.ErrProof
		}
		op.FailedAttempts++
		if op.FailedAttempts == 5 {
			op.Status = d.Failed
		}
		result, err := r.auth.database.Collection(CredentialManagementOperationCollection).ReplaceOne(tx, bson.M{"operationId": id, "status": d.Pending, "failedAttempts": op.FailedAttempts - 1}, credentialManagementOperationDocument(op))
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return d.ErrProof
		}
		return nil
	})
}
func (r *CredentialManagementRepository) Complete(ctx context.Context, digest []byte, id string, signature []byte, passwordRevision int64, event string, now time.Time) error {
	return r.tx(ctx, func(tx context.Context) error {
		now = r.auth.currentTime(now)
		s, op, err := r.bound(tx, digest, id, now)
		if err != nil {
			return err
		}
		if passwordRevision != op.PasswordRevision {
			return d.ErrProof
		}
		payload, err := r.protocol.SigningPayload(op)
		if err != nil {
			return d.ErrUnavailable
		}
		if !r.protocol.Verify(op.PublicKey, payload, signature) {
			return d.ErrProof
		}
		if op.Status == d.Completed {
			return nil
		}
		target, err := r.credential(tx, s.AuthID, op.TargetCredentialID)
		if err != nil {
			return err
		}
		_, minimum, err := r.auth.CredentialBoundsTx(tx, s.AuthID)
		if err != nil {
			return err
		}
		if target.CredentialRevision > s.AccountRevision {
			return d.ErrUnavailable
		}
		if target.RevokedAt == nil && pwd.EligibleCredential(target.CredentialRevision, minimum, s.AccountRevision) {
			if err = r.auth.revokeCredentialTargetTx(tx, s.AuthID, target.CredentialID, now); err != nil {
				return err
			}
			if err = r.audit(tx, event, "REVOKE_OTHER", s, target.CredentialID, 0, now); err != nil {
				return err
			}
		}
		op.Status = d.Completed
		op.CompletedAt = &now
		result, err := r.auth.database.Collection(CredentialManagementOperationCollection).ReplaceOne(tx, bson.M{"operationId": id, "status": d.Pending}, credentialManagementOperationDocument(op))
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return d.ErrProof
		}
		return nil
	})
}
func (r *CredentialManagementRepository) Tick(ctx context.Context) error {
	return r.tx(ctx, func(tx context.Context) error {
		now := r.auth.currentTime(time.Now())
		ids, err := r.auth.database.Collection(CredentialManagementOperationCollection).Find(tx, bson.M{"retainUntil": bson.M{"$lte": now}}, options.Find().SetProjection(bson.M{"_id": 1}).SetLimit(64))
		if err != nil {
			return err
		}
		var rows []bson.M
		if err = ids.All(tx, &rows); err != nil {
			return err
		}
		keys := bson.A{}
		for _, row := range rows {
			keys = append(keys, row["_id"])
		}
		if len(keys) > 0 {
			_, err = r.auth.database.Collection(CredentialManagementOperationCollection).DeleteMany(tx, bson.M{"_id": bson.M{"$in": keys}, "retainUntil": bson.M{"$lte": now}})
		}
		return err
	})
}
