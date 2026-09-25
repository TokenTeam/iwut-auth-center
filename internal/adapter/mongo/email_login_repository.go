package mongo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/emaillogin/domain"
	p "iwut-auth-center/internal/emaillogin/port"
)

const EmailLoginAuditCollection = "auth_email_login_audit"

type EmailLoginRepository struct {
	*EmailRepository
	loginKeyID string
}

// Login operations share the authentication collection, so pending capacity and
// expiry transitions remain global. Binding owns the single email directory.
type emailLoginDocument struct {
	OperationID           string    `bson:"operationId"`
	RequestID             string    `bson:"requestId"`
	Purpose               string    `bson:"purpose"`
	ProtocolVersion       string    `bson:"protocolVersion"`
	ServiceID             string    `bson:"serviceId"`
	ApplicationID         string    `bson:"applicationId"`
	Email                 string    `bson:"email"`
	KeyID                 string    `bson:"keyId"`
	AuthID                string    `bson:"authId"`
	CredentialID          string    `bson:"credentialId"`
	Status                string    `bson:"status"`
	PublicKey             []byte    `bson:"publicKey"`
	Fingerprint           []byte    `bson:"fingerprint"`
	Challenge             []byte    `bson:"challenge"`
	RequestMAC            []byte    `bson:"requestMac"`
	CodeMAC               []byte    `bson:"codeMac"`
	Eligible              bool      `bson:"eligible"`
	CredentialAcceptable  bool      `bson:"credentialAcceptable"`
	EmailBindingRevision  int64     `bson:"emailBindingRevision"`
	FailedAttempts        int       `bson:"failedAttempts"`
	CreatedAt             time.Time `bson:"createdAt"`
	ExpiresAt             time.Time `bson:"expiresAt"`
	ResendAfter           time.Time `bson:"resendAfter"`
	RetainUntil           time.Time `bson:"purgeAfter"`
	CompletedCredentialID string    `bson:"completedCredentialId,omitempty"`
	CompletedSessionID    string    `bson:"completedSessionId,omitempty"`
}

func loginDoc(o d.Operation) emailLoginDocument { return emailLoginDocument(o) }
func NewEmailLoginRepository(r *RegistrationRepository, keyID string, limits EmailLimits) (*EmailLoginRepository, error) {
	shared, e := NewEmailRepository(r, "login-shared-schema-only", limits)
	if e != nil || keyID == "" {
		return nil, d.ErrUnavailable
	}
	return &EmailLoginRepository{shared, keyID}, nil
}
func (r *EmailLoginRepository) Initialize(ctx context.Context, now time.Time) error {
	if e := EnsureEmailSchema(ctx, r.db); e != nil {
		return d.ErrUnavailable
	}
	_, e := r.db.Collection(AuthenticationOperationCollection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: "purpose", Value: 1}, {Key: "fingerprint", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("email_login_request_unique").SetPartialFilterExpression(bson.M{"purpose": d.Purpose})})
	if e != nil {
		return d.ErrUnavailable
	}
	return r.translate(r.WithAuthTransaction(ctx, func(tx context.Context) error {
		_, e := r.db.Collection(AuthenticationOperationCollection).UpdateMany(tx, bson.M{"purpose": d.Purpose, "status": auth.Pending, "$or": bson.A{bson.M{"keyId": bson.M{"$ne": r.loginKeyID}}, bson.M{"expiresAt": bson.M{"$lte": now}}}}, bson.M{"$set": bson.M{"status": auth.Closed}})
		return e
	}))
}
func (r *EmailLoginRepository) translate(e error) error {
	if errors.Is(e, ap.ErrUnavailable) || errors.Is(e, email.ErrUnavailable) {
		return d.ErrUnavailable
	}
	if errors.Is(e, email.ErrRate) || errors.Is(e, ap.ErrLimitExceeded) {
		return d.ErrRate
	}
	if errors.Is(e, ap.ErrAuthenticationFailed) {
		return d.ErrFailed
	}
	return e
}
func (r *EmailLoginRepository) Get(ctx context.Context, id string) (d.Operation, error) {
	var doc emailLoginDocument
	e := r.db.Collection(AuthenticationOperationCollection).FindOne(ctx, bson.M{"operationId": id, "purpose": d.Purpose}).Decode(&doc)
	if errors.Is(e, m.ErrNoDocuments) {
		return d.Operation{}, d.ErrFailed
	}
	if e != nil {
		return d.Operation{}, d.ErrUnavailable
	}
	return d.Operation(doc), nil
}
func (r *EmailLoginRepository) Begin(ctx context.Context, candidate d.Operation, source string, now time.Time) (d.Operation, bool, error) {
	var result d.Operation
	fresh := false
	err := r.WithAuthTransaction(ctx, func(tx context.Context) error {
		fresh = false
		now := r.currentTime(now)
		op := candidate
		if op.KeyID != r.loginKeyID || op.Purpose != d.Purpose || op.Status != auth.Pending || !now.Before(op.ExpiresAt) {
			return d.ErrFailed
		}
		var prior emailLoginDocument
		e := r.db.Collection(AuthenticationOperationCollection).FindOne(tx, bson.M{"purpose": d.Purpose, "fingerprint": op.Fingerprint, "requestId": op.RequestID}).Decode(&prior)
		if e == nil {
			if prior.KeyID != r.loginKeyID {
				if prior.Status == auth.Completed {
					return d.ErrCompleted
				}
				return d.ErrFailed
			}
			if !hmac.Equal(prior.RequestMAC, op.RequestMAC) {
				return d.ErrConflict
			}
			if prior.Status == auth.Completed {
				return d.ErrCompleted
			}
			if prior.Status != auth.Pending || !now.Before(prior.ExpiresAt) || !now.Before(prior.RetainUntil) {
				return d.ErrFailed
			}
			result = d.Operation(prior)
			return nil
		}
		if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		if e := r.cleanupTx(tx, now); e != nil {
			return e
		}
		// Freeze eligibility and credential ownership from one fenced snapshot.
		var binding bindingDocument
		e = r.db.Collection(EmailBindingCollection).FindOne(tx, bson.M{"email": op.Email}).Decode(&binding)
		if e == nil {
			if binding.AuthID == "" || binding.Revision <= 0 || binding.VerifiedAt.IsZero() {
				return d.ErrUnavailable
			}
			count, e := r.db.Collection(PrincipalCollection).CountDocuments(tx, bson.M{"authId": binding.AuthID, "principalType": "USER", "accountStatus": "ACTIVE"})
			if e != nil {
				return e
			}
			if count == 1 {
				op.AuthID = binding.AuthID
				op.EmailBindingRevision = binding.Revision
				op.Eligible = true
			}
		} else if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		var credential CredentialDocument
		e = r.db.Collection(CredentialCollection).FindOne(tx, bson.M{"fingerprint": op.Fingerprint}).Decode(&credential)
		switch {
		case errors.Is(e, m.ErrNoDocuments):
			op.CredentialAcceptable = true
		case e != nil:
			return e
		default:
			op.CredentialAcceptable = validCredential(credential) && credential.AuthID == op.AuthID && bytes.Equal(credential.PublicKey, op.PublicKey)
			if op.CredentialAcceptable {
				op.CredentialID = credential.CredentialID
			}
		}
		if _, e = r.db.Collection(AuthenticationOperationCollection).UpdateMany(tx, bson.M{"purpose": d.Purpose, "email": op.Email, "fingerprint": op.Fingerprint, "status": auth.Pending}, bson.M{"$set": bson.M{"status": auth.Closed}}); e != nil {
			return e
		}
		count, e := r.db.Collection(AuthenticationOperationCollection).CountDocuments(tx, bson.M{"status": auth.Pending, "expiresAt": bson.M{"$gt": now}})
		if e != nil {
			return e
		}
		if count >= int64(r.maxPending) {
			return d.ErrRate
		}
		for _, q := range []struct {
			key      string
			limit    int
			cooldown bool
		}{{"email:" + op.Email, r.limits.EmailHourly, true}, {"source:" + source, r.limits.SourceHourly, false}, {"email-login-key:" + hex.EncodeToString(op.Fingerprint), r.limits.OwnerHourly, false}} {
			if e := r.debitTx(tx, q.key, q.limit, q.cooldown, now); e != nil {
				return e
			}
		}
		if _, e = r.db.Collection(AuthenticationOperationCollection).InsertOne(tx, loginDoc(op)); e != nil {
			return e
		}
		result = op
		fresh = true
		return nil
	})
	return result, fresh, r.translate(err)
}
func (r *EmailLoginRepository) Fail(ctx context.Context, id string, now time.Time) error {
	return r.translate(r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		op, e := r.Get(tx, id)
		if e != nil {
			return e
		}
		if op.Status != auth.Pending {
			return nil
		}
		update := bson.M{"$inc": bson.M{"failedAttempts": 1}}
		if op.FailedAttempts+1 >= 5 || !now.Before(op.ExpiresAt) {
			update["$set"] = bson.M{"status": auth.Closed}
		}
		_, e = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": id, "purpose": d.Purpose, "status": auth.Pending}, update)
		return e
	}))
}
func sameLoginSnapshot(a, b d.Operation) bool {
	a.Status = ""
	b.Status = ""
	a.FailedAttempts = 0
	b.FailedAttempts = 0
	return reflect.DeepEqual(a, b)
}
func (r *EmailLoginRepository) Complete(ctx context.Context, c p.Commit, now time.Time) (string, error) {
	var result string
	err := r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		op, e := r.Get(tx, c.Operation.OperationID)
		if e != nil {
			return e
		}
		if op.Status == auth.Completed {
			return d.ErrCompleted
		}
		if op.Status != auth.Pending || op.KeyID != r.loginKeyID || op.FailedAttempts < 0 || op.FailedAttempts >= 5 || !now.Before(op.ExpiresAt) || !now.Before(op.RetainUntil) || !op.Eligible || op.EmailBindingRevision <= 0 || !sameLoginSnapshot(op, c.Operation) {
			return d.ErrFailed
		}
		if !op.CredentialAcceptable {
			return d.ErrCredential
		}
		confirmed, e := r.db.Collection(EmailBindingCollection).UpdateOne(tx, bson.M{"authId": op.AuthID, "email": op.Email, "revision": op.EmailBindingRevision}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}})
		if e != nil {
			return e
		}
		if confirmed.MatchedCount != 1 {
			return d.ErrFailed
		}
		var credential CredentialDocument
		e = r.db.Collection(CredentialCollection).FindOne(tx, bson.M{"fingerprint": op.Fingerprint}).Decode(&credential)
		if errors.Is(e, m.ErrNoDocuments) {
			if op.CredentialID != "" || c.Credential.AuthID != op.AuthID || !bytes.Equal(c.Credential.PublicKey, op.PublicKey) || !bytes.Equal(c.Credential.Fingerprint, op.Fingerprint) || !validCredential(credentialDocument(c.Credential)) {
				return d.ErrFailed
			}
			if e = r.InsertCredentialTx(tx, c.Credential); m.IsDuplicateKeyError(e) {
				return d.ErrCredential
			} else if e != nil {
				return e
			}
			credential = credentialDocument(c.Credential)
		} else if e != nil {
			return e
		}
		if !validCredential(credential) || credential.AuthID != op.AuthID || !bytes.Equal(credential.PublicKey, op.PublicKey) {
			return d.ErrCredential
		}
		session := c.Session
		session.CredentialID = credential.CredentialID
		if session.AuthID != op.AuthID || session.AuthenticationMethod != d.AuthenticationMethod || session.EmailBindingRevision != op.EmailBindingRevision {
			return d.ErrFailed
		}
		if e = r.CreateSessionTx(tx, session, now); e != nil {
			return e
		}
		updated, e := r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": op.OperationID, "purpose": d.Purpose, "status": auth.Pending, "failedAttempts": bson.M{"$lt": 5}, "expiresAt": bson.M{"$gt": now}}, bson.M{"$set": bson.M{"status": auth.Completed, "completedCredentialId": credential.CredentialID, "completedSessionId": session.SessionID}})
		if e != nil {
			return e
		}
		if updated.MatchedCount != 1 {
			return d.ErrFailed
		}
		_, e = r.db.Collection(EmailLoginAuditCollection).InsertOne(tx, bson.M{"operationId": op.OperationID, "authenticationMethod": d.AuthenticationMethod, "authId": op.AuthID, "credentialId": credential.CredentialID, "sessionId": session.SessionID, "result": "AUTHENTICATED", "at": now})
		if e != nil {
			return e
		}
		result = credential.CredentialID
		return nil
	})
	return result, r.translate(err)
}

var _ p.Repository = (*EmailLoginRepository)(nil)
