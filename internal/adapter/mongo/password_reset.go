package mongo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	ap "iwut-auth-center/internal/authentication/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
)

const PasswordResetCollection = "auth_password_resets"

type PasswordResetRepository struct {
	passwords *PasswordRepository
	protocol  p.ResetProtocol
	mail      *EmailRepository
}

func NewPasswordResetRepository(passwords *PasswordRepository, protocol p.ResetProtocol, limits EmailLimits) (*PasswordResetRepository, error) {
	if passwords == nil || protocol == nil || passwords.keyID != protocol.KeyID() {
		return nil, d.ErrUnavailable
	}
	registration, err := NewRegistrationRepository(passwords.auth.database, passwords.auth)
	if err != nil {
		return nil, err
	}
	mail, err := NewEmailRepository(registration, protocol.KeyID(), limits)
	if err != nil {
		return nil, err
	}
	return &PasswordResetRepository{passwords, protocol, mail}, nil
}

type passwordResetDocument struct {
	OperationID      string    `bson:"operationId"`
	RequestID        string    `bson:"requestId"`
	Email            string    `bson:"email"`
	AuthID           string    `bson:"authId"`
	ServiceID        string    `bson:"serviceId"`
	KeyID            string    `bson:"keyId"`
	Status           string    `bson:"status"`
	Acceptable       bool      `bson:"acceptable"`
	AccountRevision  int64     `bson:"accountRevision"`
	PasswordRevision int64     `bson:"passwordRevision"`
	RoleRevision     int64     `bson:"roleRevision"`
	FailedAttempts   int64     `bson:"failedAttempts"`
	RequestMAC       []byte    `bson:"requestMac"`
	CodeMAC          []byte    `bson:"codeMac"`
	CompletionMAC    []byte    `bson:"completionMac"`
	CreatedAt        time.Time `bson:"createdAt"`
	ExpiresAt        time.Time `bson:"expiresAt"`
	ResendAfter      time.Time `bson:"resendAfter"`
	RetainUntil      time.Time `bson:"retainUntil"`
}

func EnsurePasswordResetSchema(ctx context.Context, db *m.Database) error {
	_, err := db.Collection(PasswordResetCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "email", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}},
		{Keys: bson.D{{Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}},
		{Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	return err
}
func (r *PasswordResetRepository) read(ctx context.Context, filter bson.M) (p.Reset, error) {
	raw, err := r.passwords.auth.database.Collection(PasswordResetCollection).FindOne(ctx, filter).Raw()
	if err != nil {
		return p.Reset{}, err
	}
	fields := map[string]bson.Type{"acceptable": bson.TypeBoolean}
	for _, k := range []string{"operationId", "requestId", "email", "authId", "serviceId", "keyId", "status"} {
		fields[k] = bson.TypeString
	}
	for _, k := range []string{"accountRevision", "passwordRevision", "roleRevision", "failedAttempts"} {
		fields[k] = bson.TypeInt64
	}
	for _, k := range []string{"requestMac", "codeMac", "completionMac"} {
		fields[k] = bson.TypeBinary
	}
	for _, k := range []string{"createdAt", "expiresAt", "resendAfter", "retainUntil"} {
		fields[k] = bson.TypeDateTime
	}
	var doc passwordResetDocument
	if !identityFields(raw, fields) || bson.Unmarshal(raw, &doc) != nil {
		return p.Reset{}, d.ErrUnavailable
	}
	o := p.Reset(doc)
	key, keyErr := hex.DecodeString(o.KeyID)
	normalized, err := email.NormalizeEmail(o.Email)
	if err != nil || normalized != o.Email || !deviceprotocol.ValidID(o.OperationID) || !deviceprotocol.ValidID(o.RequestID) || o.AuthID == "" || keyErr != nil || len(key) != 32 || hex.EncodeToString(key) != o.KeyID || len(o.RequestMAC) != 32 || len(o.CodeMAC) != 32 || o.AccountRevision < 1 || o.PasswordRevision < 1 || o.RoleRevision < 1 || o.FailedAttempts < 0 || o.FailedAttempts > 5 || o.CreatedAt.IsZero() || o.CreatedAt.UnixMilli() < 0 || !o.ExpiresAt.Equal(o.CreatedAt.Add(10*time.Minute)) || !o.ResendAfter.Equal(o.CreatedAt.Add(time.Minute)) || !o.RetainUntil.Equal(o.CreatedAt.Add(24*time.Hour)) {
		return p.Reset{}, d.ErrUnavailable
	}
	if _, err = deviceprotocol.New(o.ServiceID); err != nil {
		return p.Reset{}, d.ErrUnavailable
	}
	if o.Status == "COMPLETED" {
		if !o.Acceptable || len(o.CompletionMAC) != 32 || o.FailedAttempts >= 5 {
			return p.Reset{}, d.ErrUnavailable
		}
	} else if (o.Status != "PENDING" && o.Status != "CLOSED") || len(o.CompletionMAC) != 0 || (o.Status == "PENDING" && o.FailedAttempts >= 5) {
		return p.Reset{}, d.ErrUnavailable
	}
	return o, nil
}
func (r *PasswordResetRepository) BeginReset(ctx context.Context, candidate p.Reset, code, source string, now time.Time) (p.Reset, bool, error) {
	var out p.Reset
	fresh := false
	a := r.passwords.auth
	err := a.WithAuthTransaction(ctx, func(tx context.Context) error {
		fresh = false
		observed := a.currentTime(now)
		o := candidate
		if o.KeyID != r.protocol.KeyID() || o.ServiceID != r.protocol.ServiceID() || !deviceprotocol.ValidID(o.RequestID) || !deviceprotocol.ValidID(o.OperationID) || !email.ValidCode(code) || !observed.Before(o.ExpiresAt) {
			return d.ErrInvalidInput
		}
		prior, err := r.read(tx, bson.M{"email": o.Email, "requestId": o.RequestID})
		if err == nil {
			if prior.Acceptable {
				if err = (&PasswordQuota{auth: a}).ownerRequestTx(tx, prior.AuthID, observed); err != nil {
					return err
				}
			}
			if prior.KeyID != o.KeyID || !hmac.Equal(prior.RequestMAC, o.RequestMAC) || !observed.Before(prior.RetainUntil) {
				return d.ErrReset
			}
			out = prior
			return nil
		}
		if !errors.Is(err, m.ErrNoDocuments) {
			return err
		}
		if err = sharedOperationCapacityTx(tx, a.database, observed, 10000, true); errors.Is(err, ap.ErrLimitExceeded) {
			return d.ErrLimited
		} else if err != nil {
			return err
		}
		binding, role, found, err := ResolvePrimaryEmailTx(tx, a.database, o.Email)
		if err != nil {
			return d.ErrUnavailable
		}
		if found {
			revision, err := a.AccountRevisionTx(tx, binding.AuthID)
			if err != nil && !errors.Is(err, ap.ErrAuthenticationFailed) {
				return err
			}
			if err == nil {
				record, err := r.passwords.readPasswordTx(tx, binding.AuthID)
				if err != nil {
					return d.ErrUnavailable
				}
				o.AuthID = binding.AuthID
				o.AccountRevision = revision
				o.PasswordRevision = record.Revision
				o.RoleRevision = role
				o.Acceptable = true
			}
		}
		owner := "owner:BIND:" + o.AuthID
		if o.Acceptable {
			if err = (&PasswordQuota{auth: a}).ownerRequestTx(tx, o.AuthID, observed); err != nil {
				return err
			}
		}
		if !o.Acceptable {
			owner = "email:" + o.Email
		}
		for _, q := range []struct {
			key      string
			limit    int
			cooldown bool
		}{{"email:" + o.Email, r.mail.limits.EmailHourly, true}, {"source:" + source, r.mail.limits.SourceHourly, false}} {
			if err = r.mail.debitTx(tx, q.key, q.limit, q.cooldown, observed); errors.Is(err, email.ErrRate) {
				return d.ErrLimited
			} else if err != nil {
				return err
			}
		}
		if o.Acceptable {
			if err = r.mail.debitTx(tx, owner, r.mail.limits.OwnerHourly, true, observed); errors.Is(err, email.ErrRate) {
				return d.ErrLimited
			} else if err != nil {
				return err
			}
			// The invariant is one live reset per owner; admission commits replacement
			// with the new operation, never as a side effect of a rejected request.
			var old struct {
				ID string `bson:"operationId"`
			}
			cur, e := a.database.Collection(PasswordResetCollection).Find(tx, bson.M{"authId": o.AuthID, "status": "PENDING", "expiresAt": bson.M{"$gt": observed}}, options.Find().SetLimit(2))
			if e != nil {
				return e
			}
			var rows []passwordResetDocument
			if e = cur.All(tx, &rows); e != nil {
				return e
			}
			if len(rows) > 1 {
				return d.ErrUnavailable
			}
			if len(rows) == 1 {
				old.ID = rows[0].OperationID
				if _, e = r.read(tx, bson.M{"operationId": old.ID}); e != nil {
					return e
				}
				if _, err = a.database.Collection(PasswordResetCollection).UpdateOne(tx, bson.M{"operationId": old.ID, "status": "PENDING"}, bson.M{"$set": bson.M{"status": "CLOSED"}}); err != nil {
					return err
				}
			}
		}
		o.CodeMAC, err = r.protocol.ResetCodeMAC(o.OperationID, o.AuthID, o.RoleRevision, o.PasswordRevision, o.AccountRevision, o.ExpiresAt, o.RequestMAC, code)
		if err != nil {
			return err
		}
		// An empty byte slice has a strict BSON binary representation, not null.
		o.CompletionMAC = []byte{}
		if _, err = a.database.Collection(PasswordResetCollection).InsertOne(tx, passwordResetDocument(o)); err != nil {
			return err
		}
		out = o
		fresh = true
		return nil
	})
	return out, fresh, err
}
func (r *PasswordResetRepository) bound(tx context.Context, id string, now time.Time) (p.ResetSnapshot, error) {
	o, err := r.read(tx, bson.M{"operationId": id})
	if errors.Is(err, m.ErrNoDocuments) {
		return p.ResetSnapshot{}, d.ErrReset
	}
	if err != nil {
		return p.ResetSnapshot{}, err
	}
	if o.KeyID != r.protocol.KeyID() || o.ServiceID != r.protocol.ServiceID() || !now.Before(o.RetainUntil) || o.Status == "CLOSED" || (o.Status == "PENDING" && !now.Before(o.ExpiresAt)) {
		return p.ResetSnapshot{}, d.ErrReset
	}
	if now.Before(o.CreatedAt) {
		return p.ResetSnapshot{}, d.ErrUnavailable
	}
	out := p.ResetSnapshot{Operation: o}
	if !o.Acceptable {
		return out, nil
	}
	binding, role, found, err := ResolvePrimaryEmailTx(tx, r.passwords.auth.database, o.Email)
	if err != nil {
		return out, d.ErrUnavailable
	}
	if !found || binding.AuthID != o.AuthID || role != o.RoleRevision {
		return out, d.ErrReset
	}
	revision, minimum, err := r.passwords.auth.CredentialBoundsTx(tx, o.AuthID)
	if errors.Is(err, ap.ErrAuthenticationFailed) {
		return out, d.ErrReset
	}
	if err != nil {
		return out, err
	}
	record, err := r.passwords.readPasswordTx(tx, o.AuthID)
	if err != nil {
		return out, d.ErrUnavailable
	}
	expectedAccount, expectedPassword := o.AccountRevision, o.PasswordRevision
	if o.Status == "COMPLETED" {
		expectedAccount, expectedPassword, err = d.NextRevisions(o.AccountRevision, 1, o.PasswordRevision)
		if err != nil {
			return out, d.ErrUnavailable
		}
	}
	if revision != expectedAccount || record.Revision != expectedPassword {
		return out, d.ErrReset
	}
	out.Password = record
	out.Minimum = minimum
	return out, nil
}
func (r *PasswordResetRepository) ReadReset(ctx context.Context, id string, now time.Time) (p.ResetSnapshot, error) {
	var out p.ResetSnapshot
	err := r.passwords.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		var err error
		out, err = r.bound(tx, id, r.passwords.auth.currentTime(now))
		return err
	})
	return out, err
}
func (r *PasswordResetRepository) FailReset(ctx context.Context, id string, now time.Time) error {
	return r.passwords.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		o, err := r.read(tx, bson.M{"operationId": id})
		if err != nil {
			return d.ErrUnavailable
		}
		if o.KeyID != r.protocol.KeyID() || o.Status != "PENDING" || !r.passwords.auth.currentTime(now).Before(o.ExpiresAt) {
			return d.ErrReset
		}
		status := "PENDING"
		if o.FailedAttempts == 4 {
			status = "CLOSED"
		}
		_, err = r.passwords.auth.database.Collection(PasswordResetCollection).UpdateOne(tx, bson.M{"operationId": id, "status": "PENDING", "failedAttempts": o.FailedAttempts}, bson.M{"$inc": bson.M{"failedAttempts": int64(1)}, "$set": bson.M{"status": status}})
		return err
	})
}
func (r *PasswordResetRepository) CompleteReset(ctx context.Context, before p.ResetSnapshot, material d.Material, completion []byte, now time.Time) error {
	a := r.passwords.auth
	return a.WithAuthTransaction(ctx, func(tx context.Context) error {
		observed := a.currentTime(now)
		current, err := r.bound(tx, before.Operation.OperationID, observed)
		if err != nil {
			return err
		}
		o := current.Operation
		if !o.Acceptable || !bytes.Equal(o.CodeMAC, before.Operation.CodeMAC) || !bytes.Equal(o.RequestMAC, before.Operation.RequestMAC) || len(completion) != 32 {
			return d.ErrReset
		}
		if o.Status == "COMPLETED" {
			if !hmac.Equal(completion, o.CompletionMAC) {
				return d.ErrReset
			}
			return nil
		}
		if before.Operation.Status != "PENDING" || !material.Valid() || current.Password.Revision != before.Password.Revision || current.Minimum != before.Minimum {
			return d.ErrReset
		}
		pending, err := a.database.Collection(OwnerExitCollection).CountDocuments(tx, bson.M{"authId": o.AuthID, "decision": "PENDING"}, options.Count().SetLimit(1))
		if err != nil {
			return err
		}
		if pending > 0 {
			return d.ErrConflict
		}
		revision, passwordRevision, err := d.NextRevisions(o.AccountRevision, current.Minimum, o.PasswordRevision)
		if err != nil {
			return err
		}
		if err = a.ConfirmAccountTx(tx, o.AuthID, o.AccountRevision); err != nil {
			return d.ErrReset
		}
		if err = ensurePasswordOutboxCapacityTx(tx, a.database, observed); err != nil {
			return err
		}
		result, err := a.database.Collection(PrincipalCollection).UpdateOne(tx, bson.M{"authId": o.AuthID, "accountRevision": o.AccountRevision, "minimumCredentialRevision": current.Minimum, "accountStatus": "ACTIVE"}, bson.M{"$set": bson.M{"accountRevision": revision, "minimumCredentialRevision": revision, "updatedAt": observed}})
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return d.ErrReset
		}
		result, err = a.database.Collection(PasswordCollection).ReplaceOne(tx, bson.M{"authId": o.AuthID, "passwordRevision": o.PasswordRevision}, passwordDoc(d.Record{AuthID: o.AuthID, Revision: passwordRevision, Material: material, ChangedAt: observed}))
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return d.ErrReset
		}
		if _, err = a.database.Collection(PasswordAuditCollection).InsertOne(tx, bson.M{"operationId": o.OperationID, "authId": o.AuthID, "action": "PASSWORD_RESET", "authenticationMethod": "LOGIN_EMAIL_CODE", "accountRevision": revision, "passwordRevision": passwordRevision, "at": observed}); err != nil {
			return err
		}
		if _, err = a.database.Collection(PasswordNotificationCollection).InsertOne(tx, bson.M{"eventId": o.OperationID, "authId": o.AuthID, "kind": "PASSWORD_RESET", "email": o.Email, "state": "PENDING", "attempts": int64(0), "createdAt": observed, "nextAttemptAt": observed, "retainUntil": observed.Add(24 * time.Hour)}); err != nil {
			return err
		}
		o.Status = "COMPLETED"
		o.CompletionMAC = bytes.Clone(completion)
		_, err = a.database.Collection(PasswordResetCollection).ReplaceOne(tx, bson.M{"operationId": o.OperationID, "status": "PENDING"}, passwordResetDocument(o))
		return err
	})
}

var _ p.ResetRepository = (*PasswordResetRepository)(nil)
