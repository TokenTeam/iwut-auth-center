package mongo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/emailbinding/domain"
	emailport "iwut-auth-center/internal/emailbinding/port"
	rp "iwut-auth-center/internal/registration/port"
	"math"
	"time"
)

const EmailBindingCollection = "auth_email_bindings"
const EmailOperationCollection = "auth_email_operations"
const EmailQuotaCollection = "auth_email_quotas"
const EmailAuditCollection = "auth_email_audit"

type EmailLimits struct{ OwnerHourly, EmailHourly, SourceHourly, MaxBuckets int }
type EmailRepository struct {
	*RegistrationRepository
	keyID  string
	limits EmailLimits
}
type emailOperationDocument struct {
	ID             string    `bson:"operationId"`
	RequestID      string    `bson:"requestId"`
	Owner          string    `bson:"owner"`
	Mode           string    `bson:"mode"`
	Email          string    `bson:"email"`
	KeyID          string    `bson:"keyId"`
	RequestMAC     []byte    `bson:"requestMac"`
	CodeMAC        []byte    `bson:"codeMac"`
	Revision       int64     `bson:"revision"`
	ResendAfter    time.Time `bson:"resendAfter"`
	RetainUntil    time.Time `bson:"retainUntil"`
	VerifiedAt     time.Time `bson:"verifiedAt,omitempty"`
	ResultRevision int64     `bson:"resultRevision,omitempty"`
}

func emailDoc(o emailport.Operation) emailOperationDocument {
	return emailOperationDocument{o.Proof.OperationID, o.RequestID, o.Owner, o.Mode, o.Email, o.KeyID, o.RequestMAC, o.CodeMAC, o.Revision, o.ResendAfter, o.RetainUntil, o.VerifiedAt, o.ResultRevision}
}
func (x emailOperationDocument) domain(p auth.Operation) emailport.Operation {
	return emailport.Operation{Proof: p, RequestID: x.RequestID, Owner: x.Owner, Mode: x.Mode, Email: x.Email, KeyID: x.KeyID, RequestMAC: x.RequestMAC, CodeMAC: x.CodeMAC, Revision: x.Revision, ResendAfter: x.ResendAfter, RetainUntil: x.RetainUntil, VerifiedAt: x.VerifiedAt, ResultRevision: x.ResultRevision}
}

type bindingDocument struct {
	AuthID     string    `bson:"authId"`
	Email      string    `bson:"email,omitempty"`
	Revision   int64     `bson:"revision"`
	VerifiedAt time.Time `bson:"verifiedAt,omitempty"`
	PendingID  string    `bson:"pendingId,omitempty"`
}

func NewEmailRepository(r *RegistrationRepository, keyID string, limits EmailLimits) (*EmailRepository, error) {
	if r == nil || keyID == "" || limits.OwnerHourly <= 0 || limits.EmailHourly <= 0 || limits.SourceHourly <= 0 || limits.MaxBuckets <= 0 {
		return nil, d.ErrUnavailable
	}
	return &EmailRepository{r, keyID, limits}, nil
}

// EnsureEmailSchema shares directory/quota storage without loading or rotating a binding key.
func EnsureEmailSchema(ctx context.Context, db *m.Database) error {
	indexes := map[string][]m.IndexModel{
		EmailBindingCollection:            {{Keys: bson.D{{Key: "authId", Value: 1}}, Options: options.Index().SetUnique(true)}, {Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true).SetPartialFilterExpression(bson.M{"email": bson.M{"$type": "string"}})}},
		EmailOperationCollection:          {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true)}, {Keys: bson.D{{Key: "mode", Value: 1}, {Key: "owner", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true)}, {Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}},
		EmailQuotaCollection:              {{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}},
		AuthenticationOperationCollection: {{Keys: bson.D{{Key: "purgeAfter", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}},
	}
	for name, models := range indexes {
		if _, e := db.Collection(name).Indexes().CreateMany(ctx, models); e != nil {
			return d.ErrUnavailable
		}
	}
	return nil
}
func (r *EmailRepository) Initialize(ctx context.Context, now time.Time) error {
	if err := EnsureEmailSchema(ctx, r.db); err != nil {
		return err
	}
	return r.WithAuthTransaction(ctx, func(tx context.Context) error {
		cur, e := r.db.Collection(EmailOperationCollection).Find(tx, bson.M{"keyId": bson.M{"$ne": r.keyID}})
		if e != nil {
			return e
		}
		defer cur.Close(tx)
		for cur.Next(tx) {
			var x emailOperationDocument
			if e = cur.Decode(&x); e != nil {
				return e
			}
			if _, e = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": x.ID, "status": auth.Pending}, bson.M{"$set": bson.M{"status": auth.Closed}, "$unset": associationUnset()}); e != nil {
				return e
			}
		}
		if e = cur.Err(); e != nil {
			return e
		}
		return r.cleanupTx(tx, now)
	})
}
func (r *EmailRepository) cleanupTx(ctx context.Context, now time.Time) error {
	_, e := r.db.Collection(AuthenticationOperationCollection).UpdateMany(ctx, bson.M{"purpose": bson.M{"$in": bson.A{d.RegistrationPurpose, d.BindingPurpose}}, "status": auth.Pending, "expiresAt": bson.M{"$lte": now}}, bson.M{"$set": bson.M{"status": auth.Closed}, "$unset": associationUnset()})
	if e != nil {
		return e
	}
	if _, e = r.db.Collection(EmailOperationCollection).DeleteMany(ctx, bson.M{"retainUntil": bson.M{"$lte": now}}); e != nil {
		return e
	}
	_, e = r.db.Collection(EmailQuotaCollection).DeleteMany(ctx, bson.M{"expiresAt": bson.M{"$lte": now}})
	return e
}
func (r *EmailRepository) Get(ctx context.Context, id string) (emailport.Operation, error) {
	var x emailOperationDocument
	e := r.db.Collection(EmailOperationCollection).FindOne(ctx, bson.M{"operationId": id}).Decode(&x)
	if errors.Is(e, m.ErrNoDocuments) {
		return emailport.Operation{}, d.ErrVerification
	}
	if e != nil {
		return emailport.Operation{}, d.ErrUnavailable
	}
	p, e := r.GetOperation(ctx, id)
	if e != nil {
		return emailport.Operation{}, e
	}
	return x.domain(p), nil
}
func (r *EmailRepository) Begin(ctx context.Context, o emailport.Operation, digest []byte, source string, now time.Time) (emailport.Operation, bool, error) {
	var result emailport.Operation
	fresh := false
	e := r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		fresh = false
		if len(digest) > 0 {
			caller, e := r.CheckSessionTx(tx, digest, now)
			if e != nil {
				return e
			}
			if caller.AuthID != o.Owner {
				return d.ErrSession
			}
		}
		if e := r.cleanupTx(tx, now); e != nil {
			return e
		}
		var prior emailOperationDocument
		e := r.db.Collection(EmailOperationCollection).FindOne(tx, bson.M{"mode": o.Mode, "owner": o.Owner, "requestId": o.RequestID}).Decode(&prior)
		if e == nil {
			saved, e := r.Get(tx, prior.ID)
			if e != nil {
				return e
			}
			if saved.Mode == d.Register && saved.Proof.Status == auth.Completed {
				return d.ErrCompleted
			}
			if saved.KeyID != r.keyID {
				return d.ErrVerification
			}
			if !hmac.Equal(saved.RequestMAC, o.RequestMAC) {
				return d.ErrConflict
			}
			if saved.Proof.Status != auth.Pending || !now.Before(saved.Proof.ExpiresAt) {
				return d.ErrVerification
			}
			result = saved
			return nil
		}
		if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		if o.Mode == d.Bind {
			b, e := r.bindingTx(tx, o.Owner)
			if e != nil {
				return e
			}
			if b.Revision != o.Revision || b.Revision == math.MaxInt64 {
				return d.ErrRevision
			}
			if b.Email == o.Email {
				return d.ErrActive
			}
		} else {
			count, e := r.db.Collection(CredentialCollection).CountDocuments(tx, bson.M{"fingerprint": o.Proof.LocatorValue})
			if e != nil {
				return e
			}
			if count > 0 {
				return d.ErrCredential
			}
		}
		// Closing replaced proposals and quota debit share this transaction, so a
		// rejected Begin cannot supersede a still usable code.
		cur, e := r.db.Collection(EmailOperationCollection).Find(tx, bson.M{"mode": o.Mode, "owner": o.Owner})
		if e != nil {
			return e
		}
		defer cur.Close(tx)
		for cur.Next(tx) {
			var old emailOperationDocument
			if e = cur.Decode(&old); e != nil {
				return e
			}
			if _, e = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": old.ID, "status": auth.Pending}, bson.M{"$set": bson.M{"status": auth.Closed}, "$unset": associationUnset()}); e != nil {
				return e
			}
		}
		if e = cur.Err(); e != nil {
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
		}{{"owner:" + o.Mode + ":" + o.Owner, r.limits.OwnerHourly, true}, {"email:" + o.Email, r.limits.EmailHourly, true}, {"source:" + source, r.limits.SourceHourly, false}} {
			if e := r.debitTx(tx, q.key, q.limit, q.cooldown, now); e != nil {
				return e
			}
		}
		if !now.Before(o.Proof.ExpiresAt) {
			return d.ErrVerification
		}
		if _, e = r.db.Collection(AuthenticationOperationCollection).InsertOne(tx, operationDocument(o.Proof)); e != nil {
			return e
		}
		if _, e = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": o.Proof.OperationID}, bson.M{"$set": bson.M{"purgeAfter": o.RetainUntil}}); e != nil {
			return e
		}
		if _, e = r.db.Collection(EmailOperationCollection).InsertOne(tx, emailDoc(o)); e != nil {
			return e
		}
		if o.Mode == d.Bind {
			if _, e = r.db.Collection(EmailBindingCollection).UpdateOne(tx, bson.M{"authId": o.Owner}, bson.M{"$set": bson.M{"pendingId": o.Proof.OperationID}, "$setOnInsert": bson.M{"revision": int64(0)}}, options.UpdateOne().SetUpsert(true)); e != nil {
				return e
			}
		}
		result = o
		fresh = true
		return nil
	})
	return result, fresh, e
}
func (r *EmailRepository) debitTx(ctx context.Context, key string, limit int, cooldown bool, now time.Time) error {
	sum := sha256.Sum256([]byte(key))
	id := hex.EncodeToString(sum[:])
	var bucket struct {
		Times []time.Time `bson:"times"`
	}
	e := r.db.Collection(EmailQuotaCollection).FindOne(ctx, bson.M{"_id": id}).Decode(&bucket)
	if errors.Is(e, m.ErrNoDocuments) {
		n, e := r.db.Collection(EmailQuotaCollection).CountDocuments(ctx, bson.M{})
		if e != nil {
			return e
		}
		if n >= int64(r.limits.MaxBuckets) {
			return d.ErrRate
		}
	} else if e != nil {
		return e
	}
	times := make([]time.Time, 0, len(bucket.Times)+1)
	for _, at := range bucket.Times {
		if at.After(now.Add(-time.Hour)) {
			times = append(times, at)
		}
	}
	if len(times) >= limit || cooldown && len(times) > 0 && now.Sub(times[len(times)-1]) < time.Minute {
		return d.ErrRate
	}
	times = append(times, now)
	_, e = r.db.Collection(EmailQuotaCollection).UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"times": times, "expiresAt": now.Add(time.Hour)}}, options.UpdateOne().SetUpsert(true))
	return e
}
func (r *EmailRepository) Fail(ctx context.Context, id string, now time.Time) error {
	return r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		p, e := r.GetOperation(tx, id)
		if e != nil {
			return e
		}
		if p.Status != auth.Pending {
			return nil
		}
		update := bson.M{"$inc": bson.M{"failedAttempts": 1}}
		if p.FailedAttempts+1 >= 5 || !now.Before(p.ExpiresAt) {
			update["$set"] = bson.M{"status": auth.Closed}
			update["$unset"] = associationUnset()
		}
		_, e = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": id}, update)
		return e
	})
}
func (r *EmailRepository) bindingTx(ctx context.Context, id string) (bindingDocument, error) {
	var b bindingDocument
	e := r.db.Collection(EmailBindingCollection).FindOne(ctx, bson.M{"authId": id}).Decode(&b)
	if errors.Is(e, m.ErrNoDocuments) {
		return bindingDocument{AuthID: id}, nil
	}
	return b, e
}
func (r *EmailRepository) Complete(ctx context.Context, expected emailport.Operation, digest []byte, c *rp.RegistrationCommit, now time.Time) (emailport.Activated, error) {
	var result emailport.Activated
	e := r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		op, e := r.Get(tx, expected.Proof.OperationID)
		if e != nil {
			return e
		}
		if op.Mode == d.Bind {
			caller, e := r.CheckSessionTx(tx, digest, now)
			if e != nil {
				return e
			}
			if caller.AuthID != op.Owner {
				return d.ErrVerification
			}
		} else if len(digest) > 0 {
			return d.ErrFlow
		}
		if op.Mode == d.Register && op.Proof.Status == auth.Completed {
			return d.ErrCompleted
		}
		if op.KeyID != r.keyID || !now.Before(op.RetainUntil) || !bytes.Equal(op.CodeMAC, expected.CodeMAC) || !bytes.Equal(op.RequestMAC, expected.RequestMAC) {
			return d.ErrVerification
		}
		result = emailport.Activated{OperationID: op.Proof.OperationID, Mode: op.Mode, Email: op.Email, VerifiedAt: op.VerifiedAt, Revision: op.ResultRevision}
		if op.Mode == d.Bind && op.Proof.Status == auth.Completed {
			return nil
		}
		if op.Proof.Status != auth.Pending || op.Proof.FailedAttempts >= 5 || !now.Before(op.Proof.ExpiresAt) || !sameRegistrationSnapshot(op.Proof, expected.Proof) {
			return d.ErrVerification
		}
		authID := op.Owner
		revision := int64(1)
		if op.Mode == d.Bind {
			b, e := r.bindingTx(tx, op.Owner)
			if e != nil {
				return e
			}
			if b.Revision != op.Revision || b.PendingID != op.Proof.OperationID || b.Revision == math.MaxInt64 {
				return d.ErrRevision
			}
			revision = b.Revision + 1
		}
		count, e := r.db.Collection(EmailBindingCollection).CountDocuments(tx, bson.M{"email": op.Email})
		if e != nil {
			return e
		}
		if count > 0 {
			return d.ErrOccupied
		}
		if op.Mode == d.Register {
			if c == nil || !sameRegistrationSnapshot(op.Proof, c.Operation) || !bytes.Equal(c.Credential.PublicKey, op.Proof.PublicKey) || !bytes.Equal(c.Credential.Fingerprint, op.Proof.LocatorValue) || !bytes.Equal(c.Association.LookupKey, op.Proof.LookupKey) || c.Association.KeyVersion != op.Proof.KeyVersion || c.Credential.AuthID != c.Session.AuthID || c.Credential.CredentialID != c.Session.CredentialID {
				return d.ErrVerification
			}
			authID = c.Credential.AuthID
			if e = r.CreateRegisteredUserTx(tx, *c, now); e != nil {
				return e
			}
		}
		_, e = r.db.Collection(EmailBindingCollection).UpdateOne(tx, bson.M{"authId": authID}, bson.M{"$set": bson.M{"email": op.Email, "revision": revision, "verifiedAt": now}, "$unset": bson.M{"pendingId": ""}}, options.UpdateOne().SetUpsert(true))
		if m.IsDuplicateKeyError(e) {
			return d.ErrOccupied
		}
		if e != nil {
			return e
		}
		set := bson.M{"status": auth.Completed}
		if c != nil {
			set["completedAuthId"] = authID
			set["completedCredentialId"] = c.Credential.CredentialID
			set["completedSessionId"] = c.Session.SessionID
		}
		if _, e = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": op.Proof.OperationID}, bson.M{"$set": set, "$unset": associationUnset()}); e != nil {
			return e
		}
		if _, e = r.db.Collection(EmailOperationCollection).UpdateOne(tx, bson.M{"operationId": op.Proof.OperationID}, bson.M{"$set": bson.M{"verifiedAt": now, "resultRevision": revision, "retainUntil": now.Add(24 * time.Hour)}}); e != nil {
			return e
		}
		if _, e = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": op.Proof.OperationID}, bson.M{"$set": bson.M{"purgeAfter": now.Add(24 * time.Hour)}}); e != nil {
			return e
		}
		if _, e = r.db.Collection(EmailAuditCollection).InsertOne(tx, bson.M{"authId": authID, "operationId": op.Proof.OperationID, "revision": revision, "at": now, "result": "ACTIVATED"}); e != nil {
			return e
		}
		result.VerifiedAt = now
		result.Revision = revision
		return nil
	})
	return result, e
}
func (r *EmailRepository) Own(ctx context.Context, digest []byte, now time.Time) (emailport.Binding, error) {
	var result emailport.Binding
	e := r.WithAuthTransaction(ctx, func(tx context.Context) error {
		now := r.currentTime(now)
		caller, e := r.CheckSessionTx(tx, digest, now)
		if e != nil {
			return e
		}
		b, e := r.bindingTx(tx, caller.AuthID)
		if e != nil {
			return e
		}
		result = emailport.Binding{AuthID: b.AuthID, Email: b.Email, Revision: b.Revision, VerifiedAt: b.VerifiedAt, PendingID: b.PendingID}
		if b.PendingID != "" {
			op, e := r.Get(tx, b.PendingID)
			if e != nil && !errors.Is(e, d.ErrVerification) && !errors.Is(e, ap.ErrNotFound) {
				return e
			}
			if e == nil && op.Mode == d.Bind && op.Owner == caller.AuthID && op.KeyID == r.keyID && op.Proof.Status == auth.Pending && now.Before(op.Proof.ExpiresAt) && op.Proof.FailedAttempts < 5 {
				result.Pending = &op
			}
		}
		return nil
	})
	return result, e
}
