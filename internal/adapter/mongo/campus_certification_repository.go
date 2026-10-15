package mongo

import (
	"context"
	"crypto/hmac"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/campuscertification/domain"
	"iwut-auth-center/internal/campuscertification/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	"time"
)

const CampusCertificationCollection = "auth_campus_certifications"
const CampusVerificationCollection = "auth_campus_verifications"
const CampusAuditCollection = "auth_campus_audit"

type CampusCertificationRepository struct{ *EmailRepository }
type campusVerificationDocument struct {
	OperationID     string    `bson:"operationId"`
	AuthID          string    `bson:"authId"`
	AccountRevision int64     `bson:"accountRevision"`
	RequestID       string    `bson:"requestId"`
	Purpose         string    `bson:"purpose"`
	Email           string    `bson:"email"`
	KeyID           string    `bson:"keyId"`
	RequestMAC      []byte    `bson:"requestMac"`
	CodeMAC         []byte    `bson:"codeMac"`
	ResendAfter     time.Time `bson:"resendAfter"`
	RetainUntil     time.Time `bson:"retainUntil"`
}

func campusDoc(op port.Operation) campusVerificationDocument {
	return campusVerificationDocument{op.Proof.OperationID, op.Proof.AuthID, op.Proof.AccountRevision, op.RequestID, d.Purpose, op.Email, op.KeyID, op.RequestMAC, op.CodeMAC, op.ResendAfter, op.RetainUntil}
}
func (x campusVerificationDocument) operation(p auth.Operation) port.Operation {
	return port.Operation{Proof: p, RequestID: x.RequestID, Email: x.Email, KeyID: x.KeyID, RequestMAC: x.RequestMAC, CodeMAC: x.CodeMAC, ResendAfter: x.ResendAfter, RetainUntil: x.RetainUntil}
}

func NewCampusCertificationRepository(r *RegistrationRepository, keyID string, limits EmailLimits) (*CampusCertificationRepository, error) {
	e, err := NewEmailRepository(r, keyID, limits)
	if err != nil {
		return nil, d.ErrUnavailable
	}
	return &CampusCertificationRepository{e}, nil
}

// EnsureCampusSchema is independent of the verification API deployment gate and
// key. USER initialization must call it before school-email registration.
func EnsureCampusSchema(ctx context.Context, db *m.Database) error {
	if db == nil {
		return d.ErrUnavailable
	}
	indexes := map[string][]m.IndexModel{
		CampusCertificationCollection: {{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "institution", Value: 1}}, Options: options.Index().SetUnique(true)}},
		CampusVerificationCollection:  {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true)}, {Keys: bson.D{{Key: "authId", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true)}, {Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}},
		CampusAuditCollection:         {{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "institution", Value: 1}}, Options: options.Index().SetUnique(true)}},
	}
	for name, models := range indexes {
		if _, err := db.Collection(name).Indexes().CreateMany(ctx, models); err != nil {
			return d.ErrUnavailable
		}
	}
	return nil
}

// ReadCampusCertificationTx never repairs missing or malformed evidence. The
// caller supplies its existing authentication transaction and current gate.
func ReadCampusCertificationTx(ctx context.Context, db *m.Database, authID string) (d.Certification, error) {
	if db == nil || authID == "" {
		return d.Certification{}, d.ErrUnavailable
	}
	cur, err := db.Collection(CampusCertificationCollection).Find(ctx, bson.M{"authId": authID}, options.Find().SetLimit(2))
	if err != nil {
		return d.Certification{}, d.ErrUnavailable
	}
	defer cur.Close(ctx)
	var docs []bson.M
	if err = cur.All(ctx, &docs); err != nil {
		return d.Certification{}, d.ErrUnavailable
	}
	if len(docs) == 0 {
		return d.Certification{}, d.ErrNotFound
	}
	if len(docs) != 1 {
		return d.Certification{}, d.ErrUnavailable
	}
	row := docs[0]
	for key := range row {
		if key != "_id" && key != "authId" && key != "institution" && key != "certifiedAt" {
			return d.Certification{}, d.ErrUnavailable
		}
	}
	id, idOK := row["authId"].(string)
	institution, institutionOK := row["institution"].(string)
	at, timeOK := row["certifiedAt"].(bson.DateTime)
	if !idOK || id != authID || !institutionOK || !timeOK {
		return d.Certification{}, d.ErrUnavailable
	}
	result := d.Certification{Institution: institution, CertifiedAt: at.Time().UTC()}
	if !result.Valid() {
		return d.Certification{}, d.ErrUnavailable
	}
	return result, nil
}

// EnsureCampusCertificationTx is used after server-side verified REGISTER and
// independent campus verification, only inside the caller's Auth transaction.
// Existing immutable evidence and certification time are never overwritten.
func EnsureCampusCertificationTx(ctx context.Context, db *m.Database, authID string, now time.Time) error {
	if db == nil || authID == "" || m.SessionFromContext(ctx) == nil {
		return d.ErrUnavailable
	}
	_, err := ReadCampusCertificationTx(ctx, db, authID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, d.ErrNotFound) {
		return err
	}
	now = now.UTC().Truncate(time.Millisecond)
	if !(d.Certification{Institution: d.Institution, CertifiedAt: now}).Valid() {
		return d.ErrUnavailable
	}
	if _, err = db.Collection(CampusCertificationCollection).InsertOne(ctx, bson.M{"authId": authID, "institution": d.Institution, "certifiedAt": now}); err != nil {
		return err
	}
	_, err = db.Collection(CampusAuditCollection).InsertOne(ctx, bson.M{"authId": authID, "institution": d.Institution, "at": now, "result": "CERTIFIED"})
	return err
}

func (r *CampusCertificationRepository) Initialize(ctx context.Context, now time.Time) error {
	if err := EnsureCampusSchema(ctx, r.db); err != nil {
		return err
	}
	if err := EnsureEmailSchema(ctx, r.db); err != nil {
		return d.ErrUnavailable
	}
	return r.campusTransaction(ctx, func(tx context.Context) error {
		cur, err := r.db.Collection(CampusVerificationCollection).Find(tx, bson.M{"keyId": bson.M{"$ne": r.keyID}})
		if err != nil {
			return err
		}
		defer cur.Close(tx)
		for cur.Next(tx) {
			var old campusVerificationDocument
			if err = cur.Decode(&old); err != nil {
				return err
			}
			if _, err = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": old.OperationID, "purpose": d.Purpose, "status": auth.Pending}, bson.M{"$set": bson.M{"status": auth.Closed}}); err != nil {
				return err
			}
		}
		if err = cur.Err(); err != nil {
			return err
		}
		return r.campusCleanupTx(tx, r.currentTime(now))
	})
}
func (r *CampusCertificationRepository) campusCleanupTx(ctx context.Context, now time.Time) error {
	if _, err := r.db.Collection(AuthenticationOperationCollection).UpdateMany(ctx, bson.M{"purpose": d.Purpose, "status": auth.Pending, "expiresAt": bson.M{"$lte": now}}, bson.M{"$set": bson.M{"status": auth.Closed}}); err != nil {
		return err
	}
	if _, err := r.db.Collection(CampusVerificationCollection).DeleteMany(ctx, bson.M{"retainUntil": bson.M{"$lte": now}}); err != nil {
		return err
	}
	_, err := r.db.Collection(EmailQuotaCollection).DeleteMany(ctx, bson.M{"expiresAt": bson.M{"$lte": now}})
	return err
}

func validCampusOperation(op port.Operation) bool {
	p := op.Proof
	emailAddress, err := email.NormalizeEmail(op.Email)
	return err == nil && emailAddress == op.Email && d.IsWHUTEmail(op.Email) && deviceprotocol.ValidID(p.OperationID) && deviceprotocol.ValidID(op.RequestID) && p.Purpose == d.Purpose && p.AuthID != "" && p.AccountRevision > 0 && p.ServiceID != "" && p.ApplicationID == auth.ApplicationID && p.Acceptable && p.CreatedAt.UnixMilli() > 0 && p.ExpiresAt.Equal(p.CreatedAt.Add(10*time.Minute)) && op.ResendAfter.Equal(p.CreatedAt.Add(time.Minute)) && op.RetainUntil.Equal(p.CreatedAt.Add(24*time.Hour)) && len(op.KeyID) == 64 && len(op.RequestMAC) == 32 && len(op.CodeMAC) == 32 && p.FailedAttempts >= 0 && p.FailedAttempts <= 5 && (p.Status == auth.Pending || p.Status == auth.Closed || p.Status == auth.Completed)
}

func (r *CampusCertificationRepository) Get(ctx context.Context, id string) (port.Operation, error) {
	var row campusVerificationDocument
	err := r.db.Collection(CampusVerificationCollection).FindOne(ctx, bson.M{"operationId": id}).Decode(&row)
	if errors.Is(err, m.ErrNoDocuments) {
		return port.Operation{}, d.ErrVerification
	}
	if err != nil {
		return port.Operation{}, d.ErrUnavailable
	}
	if row.RetainUntil.UnixMilli() <= 0 {
		return port.Operation{}, d.ErrUnavailable
	}
	if !r.currentTime(time.Time{}).Before(row.RetainUntil) {
		return port.Operation{}, d.ErrVerification
	}
	p, err := r.GetOperation(ctx, id)
	if err != nil {
		return port.Operation{}, d.ErrUnavailable
	}
	op := row.operation(p)
	if row.Purpose != d.Purpose || row.AuthID != p.AuthID || row.AccountRevision != p.AccountRevision || !validCampusOperation(op) {
		return port.Operation{}, d.ErrUnavailable
	}
	return op, nil
}

func (r *CampusCertificationRepository) Begin(ctx context.Context, op port.Operation, digest []byte, source string, now time.Time) (port.Operation, bool, error) {
	var result port.Operation
	fresh := false
	err := r.campusTransaction(ctx, func(tx context.Context) error {
		fresh = false
		now := r.currentTime(now)
		caller, err := r.CheckSessionTx(tx, digest, now)
		if err != nil {
			return err
		}
		if caller.AuthID != op.Proof.AuthID || caller.AccountRevision != op.Proof.AccountRevision {
			return d.ErrVerification
		}
		if !validCampusOperation(op) || op.KeyID != r.keyID {
			return d.ErrUnavailable
		}
		if err = r.campusCleanupTx(tx, now); err != nil {
			return err
		}
		_, err = ReadCampusCertificationTx(tx, r.db, caller.AuthID)
		if err == nil {
			return d.ErrCertified
		}
		if !errors.Is(err, d.ErrNotFound) {
			return err
		}
		var prior campusVerificationDocument
		err = r.db.Collection(CampusVerificationCollection).FindOne(tx, bson.M{"authId": caller.AuthID, "requestId": op.RequestID}).Decode(&prior)
		if err == nil {
			saved, err := r.Get(tx, prior.OperationID)
			if err != nil {
				return err
			}
			if saved.Email != op.Email || saved.Proof.AccountRevision != op.Proof.AccountRevision {
				return d.ErrConflict
			}
			now = r.currentTime(now)
			if saved.KeyID != r.keyID || saved.Proof.Status != auth.Pending || !now.Before(saved.Proof.ExpiresAt) {
				return d.ErrVerification
			}
			if !hmac.Equal(saved.RequestMAC, op.RequestMAC) {
				return d.ErrConflict
			}
			result = saved
			return nil
		}
		if !errors.Is(err, m.ErrNoDocuments) {
			return err
		}
		// Replacing and quota debit are atomic: rejected Begin preserves the old code.
		if _, err = r.db.Collection(AuthenticationOperationCollection).UpdateMany(tx, bson.M{"purpose": d.Purpose, "authId": caller.AuthID, "status": auth.Pending}, bson.M{"$set": bson.M{"status": auth.Closed}}); err != nil {
			return err
		}
		count, err := r.db.Collection(AuthenticationOperationCollection).CountDocuments(tx, bson.M{"status": auth.Pending, "expiresAt": bson.M{"$gt": now}})
		if err != nil {
			return err
		}
		if count >= int64(r.maxPending) {
			return d.ErrRate
		}
		for _, q := range []struct {
			key      string
			limit    int
			cooldown bool
		}{{"owner:" + email.Bind + ":" + caller.AuthID, r.limits.OwnerHourly, true}, {"email:" + op.Email, r.limits.EmailHourly, true}, {"source:" + source, r.limits.SourceHourly, false}} {
			if err = r.debitTx(tx, q.key, q.limit, q.cooldown, now); err != nil {
				return err
			}
		}
		// The snapshot and quota reads may take time. Do not rely on admission's
		// timestamp for either the final Session or the proof expiry gate.
		now = r.currentTime(now)
		if _, err = r.CheckSessionTx(tx, digest, now); err != nil {
			return err
		}
		if !now.Before(op.Proof.ExpiresAt) {
			return d.ErrVerification
		}
		proof := operationDocument(op.Proof)
		if _, err = r.db.Collection(AuthenticationOperationCollection).InsertOne(tx, proof); err != nil {
			return err
		}
		if _, err = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": op.Proof.OperationID}, bson.M{"$set": bson.M{"purgeAfter": op.RetainUntil}}); err != nil {
			return err
		}
		if _, err = r.db.Collection(CampusVerificationCollection).InsertOne(tx, campusDoc(op)); err != nil {
			return err
		}
		result = op
		fresh = true
		return nil
	})
	return result, fresh, err
}

func (r *CampusCertificationRepository) Complete(ctx context.Context, expected port.Operation, digest []byte, now time.Time) (d.Certification, error) {
	var result d.Certification
	var outcome error
	err := r.campusTransaction(ctx, func(tx context.Context) error {
		result = d.Certification{}
		outcome = nil
		now := r.currentTime(now)
		caller, err := r.CheckSessionTx(tx, digest, now)
		if err != nil {
			return err
		}
		op, err := r.Get(tx, expected.Proof.OperationID)
		if err != nil {
			return err
		}
		now = r.currentTime(now)
		caller, err = r.CheckSessionTx(tx, digest, now)
		if err != nil {
			return err
		}
		if caller.AuthID != op.Proof.AuthID || caller.AccountRevision != op.Proof.AccountRevision {
			return d.ErrVerification
		}
		if op.KeyID != r.keyID || !now.Before(op.RetainUntil) || !hmac.Equal(op.RequestMAC, expected.RequestMAC) || op.Email != expected.Email || op.Proof.AccountRevision != expected.Proof.AccountRevision {
			return d.ErrVerification
		}
		goodCode := hmac.Equal(op.CodeMAC, expected.CodeMAC)
		if op.Proof.Status == auth.Completed {
			if !goodCode {
				return d.ErrVerification
			}
			result, err = ReadCampusCertificationTx(tx, r.db, caller.AuthID)
			if errors.Is(err, d.ErrNotFound) {
				return d.ErrUnavailable
			}
			return err
		}
		if op.Proof.Status != auth.Pending {
			return d.ErrVerification
		}
		if !goodCode || !now.Before(op.Proof.ExpiresAt) || op.Proof.FailedAttempts >= 5 {
			update := bson.M{"$inc": bson.M{"failedAttempts": 1}}
			if op.Proof.FailedAttempts+1 >= 5 || !now.Before(op.Proof.ExpiresAt) {
				update["$set"] = bson.M{"status": auth.Closed}
			}
			if _, err = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": op.Proof.OperationID, "status": auth.Pending}, update); err != nil {
				return err
			}
			outcome = d.ErrVerification
			return nil // commit the failed attempt, then report failure
		}
		if err = EnsureCampusCertificationTx(tx, r.db, caller.AuthID, now); err != nil {
			return err
		}
		now = r.currentTime(now)
		if !now.Before(op.Proof.ExpiresAt) {
			return d.ErrVerification // rolls back a fact inserted during a slow write
		}
		if _, err = r.CheckSessionTx(tx, digest, now); err != nil {
			return err
		}
		if _, err = r.db.Collection(AuthenticationOperationCollection).UpdateOne(tx, bson.M{"operationId": op.Proof.OperationID, "purpose": d.Purpose, "status": auth.Pending}, bson.M{"$set": bson.M{"status": auth.Completed, "completedAuthId": caller.AuthID}}); err != nil {
			return err
		}
		result, err = ReadCampusCertificationTx(tx, r.db, caller.AuthID)
		return err
	})
	if err != nil {
		return d.Certification{}, err
	}
	return result, outcome
}
func (r *CampusCertificationRepository) Own(ctx context.Context, digest []byte, now time.Time) (d.Certification, error) {
	var result d.Certification
	err := r.campusTransaction(ctx, func(tx context.Context) error {
		caller, err := r.CheckSessionTx(tx, digest, r.currentTime(now))
		if err != nil {
			return err
		}
		result, err = ReadCampusCertificationTx(tx, r.db, caller.AuthID)
		return err
	})
	return result, err
}

func (r *CampusCertificationRepository) campusTransaction(ctx context.Context, fn func(context.Context) error) error {
	err := r.WithAuthTransaction(ctx, fn)
	if err == nil {
		return nil
	}
	for _, known := range d.Errors {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, ap.ErrSessionInvalid) || errors.Is(err, ap.ErrAuthenticationFailed) {
		return d.ErrSession
	}
	if errors.Is(err, email.ErrRate) {
		return d.ErrRate
	}
	return d.ErrUnavailable
}

var _ port.Repository = (*CampusCertificationRepository)(nil)
