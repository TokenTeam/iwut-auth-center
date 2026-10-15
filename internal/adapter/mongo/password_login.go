package mongo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
	"reflect"
	"strings"
	"time"
)

const PasswordLoginCollection = "auth_password_logins"

type PasswordLoginRepository struct {
	passwords *PasswordRepository
	protocol  p.LoginProtocol
}

func NewPasswordLoginRepository(passwords *PasswordRepository, protocol p.LoginProtocol) (*PasswordLoginRepository, error) {
	if passwords == nil || protocol == nil || passwords.keyID != protocol.KeyID() {
		return nil, d.ErrUnavailable
	}
	return &PasswordLoginRepository{passwords, protocol}, nil
}

type passwordLoginDocument struct {
	OperationID      string    `bson:"operationId"`
	RequestID        string    `bson:"requestId"`
	Email            string    `bson:"email"`
	AddressKey       string    `bson:"addressKey"`
	AuthID           string    `bson:"authId"`
	ServiceID        string    `bson:"serviceId"`
	KeyID            string    `bson:"keyId"`
	Status           string    `bson:"status"`
	Acceptable       bool      `bson:"acceptable"`
	AccountRevision  int64     `bson:"accountRevision"`
	PasswordRevision int64     `bson:"passwordRevision"`
	RoleRevision     int64     `bson:"roleRevision"`
	FailedAttempts   int64     `bson:"failedAttempts"`
	PublicKey        []byte    `bson:"publicKey"`
	Fingerprint      []byte    `bson:"fingerprint"`
	Challenge        []byte    `bson:"challenge"`
	RequestMAC       []byte    `bson:"requestMac"`
	CreatedAt        time.Time `bson:"createdAt"`
	ExpiresAt        time.Time `bson:"expiresAt"`
	RetainUntil      time.Time `bson:"retainUntil"`
}

func EnsurePasswordLoginSchema(ctx context.Context, db *m.Database) error {
	_, err := db.Collection(PasswordLoginCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "addressKey", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}},
		{Keys: bson.D{{Key: "addressKey", Value: 1}, {Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}},
		{Keys: bson.D{{Key: "status", Value: 1}, {Key: "expiresAt", Value: 1}}},
		{Keys: bson.D{{Key: "retainUntil", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	return err
}
func (r *PasswordLoginRepository) read(ctx context.Context, filter bson.M) (p.Login, error) {
	raw, err := r.passwords.auth.database.Collection(PasswordLoginCollection).FindOne(ctx, filter).Raw()
	if err != nil {
		return p.Login{}, err
	}
	fields := map[string]bson.Type{"acceptable": bson.TypeBoolean}
	for _, k := range []string{"operationId", "requestId", "email", "addressKey", "authId", "serviceId", "keyId", "status"} {
		fields[k] = bson.TypeString
	}
	for _, k := range []string{"accountRevision", "passwordRevision", "roleRevision", "failedAttempts"} {
		fields[k] = bson.TypeInt64
	}
	for _, k := range []string{"publicKey", "fingerprint", "challenge", "requestMac"} {
		fields[k] = bson.TypeBinary
	}
	for _, k := range []string{"createdAt", "expiresAt", "retainUntil"} {
		fields[k] = bson.TypeDateTime
	}
	var doc passwordLoginDocument
	if !identityFields(raw, fields) || bson.Unmarshal(raw, &doc) != nil {
		return p.Login{}, d.ErrUnavailable
	}
	o := p.Login(doc)
	normalized, err := email.NormalizeEmail(o.Email)
	device, e := deviceprotocol.New(o.ServiceID)
	key, ke := hex.DecodeString(o.KeyID)
	addressKey, ae := hex.DecodeString(strings.TrimPrefix(o.AddressKey, "email:"))
	if err != nil || normalized != o.Email || e != nil || !deviceprotocol.ValidID(o.OperationID) || !deviceprotocol.ValidID(o.RequestID) || o.AuthID == "" || ke != nil || len(key) != 32 || hex.EncodeToString(key) != o.KeyID || ae != nil || len(addressKey) != 32 || "email:"+hex.EncodeToString(addressKey) != o.AddressKey || o.AccountRevision < 1 || o.PasswordRevision < 1 || o.RoleRevision < 1 || o.FailedAttempts < 0 || o.FailedAttempts > 5 || len(o.Challenge) != 32 || len(o.RequestMAC) != 32 || o.CreatedAt.IsZero() || o.CreatedAt.UnixMilli() < 0 || !o.ExpiresAt.Equal(o.CreatedAt.Add(5*time.Minute)) || !o.RetainUntil.Equal(o.CreatedAt.Add(24*time.Hour)) {
		return p.Login{}, d.ErrUnavailable
	}
	fp, err := device.Fingerprint(o.PublicKey)
	if err != nil || !bytes.Equal(fp, o.Fingerprint) || (o.Status != auth.Pending && o.Status != auth.Completed && o.Status != auth.Closed) || (o.Status != auth.Closed && o.FailedAttempts >= 5) || (o.Status == auth.Completed && !o.Acceptable) {
		return p.Login{}, d.ErrUnavailable
	}
	tag, err := r.protocol.LoginRequestMAC(o.RequestID, o.Email, o.PublicKey)
	if err != nil {
		return p.Login{}, d.ErrUnavailable
	}
	if o.KeyID == r.protocol.KeyID() && o.ServiceID == r.protocol.ServiceID() && !hmac.Equal(tag, o.RequestMAC) {
		return p.Login{}, d.ErrUnavailable
	}
	return o, nil
}
func passwordLoginError(err error) error {
	if errors.Is(err, ap.ErrAuthenticationFailed) || errors.Is(err, ap.ErrCredentialRegistered) || errors.Is(err, ap.ErrCredentialReauthRequired) || errors.Is(err, ap.ErrNotFound) {
		return d.ErrAuthentication
	}
	if errors.Is(err, ap.ErrLimitExceeded) {
		return d.ErrLimited
	}
	return err
}
func (r *PasswordLoginRepository) BeginLogin(ctx context.Context, candidate p.Login, now time.Time) (p.Login, error) {
	var out p.Login
	a := r.passwords.auth
	err := a.WithAuthTransaction(ctx, func(tx context.Context) error {
		observed := a.currentTime(now)
		o := candidate
		if o.KeyID != r.protocol.KeyID() || o.ServiceID != r.protocol.ServiceID() || !observed.Before(o.ExpiresAt) {
			return d.ErrAuthentication
		}
		prior, err := r.read(tx, bson.M{"addressKey": o.AddressKey, "requestId": o.RequestID})
		if err == nil {
			if prior.KeyID != o.KeyID || prior.ServiceID != o.ServiceID || !observed.Before(prior.RetainUntil) {
				return d.ErrAuthentication
			}
			if !hmac.Equal(prior.RequestMAC, o.RequestMAC) {
				return d.ErrRequestConflict
			}
			if prior.Acceptable {
				if err = (&PasswordQuota{auth: a}).ownerRequestTx(tx, prior.AuthID, observed); err != nil {
					return err
				}
			}
			out = prior
			return nil
		}
		if !errors.Is(err, m.ErrNoDocuments) {
			return err
		}
		if err = sharedOperationCapacityTx(tx, a.database, observed, 10000, true); err != nil {
			return passwordLoginError(err)
		}
		binding, role, found, err := ResolvePrimaryEmailTx(tx, a.database, o.Email)
		if err != nil {
			return d.ErrUnavailable
		}
		if found {
			revision, e := a.AccountRevisionTx(tx, binding.AuthID)
			if e != nil && !errors.Is(e, ap.ErrAuthenticationFailed) {
				return e
			}
			if e == nil {
				record, e := r.passwords.readPasswordTx(tx, binding.AuthID)
				if e != nil {
					return d.ErrUnavailable
				}
				o.AuthID = binding.AuthID
				o.AccountRevision = revision
				o.PasswordRevision = record.Revision
				o.RoleRevision = role
				o.Acceptable = true
			}
		}
		filter := bson.M{"addressKey": o.AddressKey, "status": auth.Pending, "expiresAt": bson.M{"$gt": observed}}
		if o.Acceptable {
			if err = (&PasswordQuota{auth: a}).ownerRequestTx(tx, o.AuthID, observed); err != nil {
				return err
			}
			filter = bson.M{"authId": o.AuthID, "status": auth.Pending, "expiresAt": bson.M{"$gt": observed}}
		}
		count, err := a.database.Collection(PasswordLoginCollection).CountDocuments(tx, filter, options.Count().SetLimit(5))
		if err != nil {
			return err
		}
		if count >= 5 {
			return d.ErrLimited
		}
		if _, err = a.database.Collection(PasswordLoginCollection).InsertOne(tx, passwordLoginDocument(o)); err != nil {
			return err
		}
		out = o
		return nil
	})
	return out, passwordLoginError(err)
}

// bound deliberately preserves a placeholder forever. A later registration,
// role switch or restore cannot turn a previously unacceptable Begin into login.
func (r *PasswordLoginRepository) bound(tx context.Context, id string, now time.Time) (p.LoginSnapshot, error) {
	o, err := r.read(tx, bson.M{"operationId": id})
	if errors.Is(err, m.ErrNoDocuments) {
		return p.LoginSnapshot{}, d.ErrAuthentication
	}
	if err != nil {
		return p.LoginSnapshot{}, err
	}
	if o.KeyID != r.protocol.KeyID() || o.ServiceID != r.protocol.ServiceID() || !now.Before(o.RetainUntil) {
		return p.LoginSnapshot{}, d.ErrAuthentication
	}
	if now.Before(o.CreatedAt) {
		return p.LoginSnapshot{}, d.ErrUnavailable
	}
	if o.Status == auth.Completed {
		return p.LoginSnapshot{}, d.ErrLoginCompleted
	}
	if o.Status != auth.Pending || o.FailedAttempts >= 5 || !now.Before(o.ExpiresAt) {
		return p.LoginSnapshot{}, d.ErrAuthentication
	}
	s := p.LoginSnapshot{Operation: o}
	if !o.Acceptable {
		return s, nil
	}
	a := r.passwords.auth
	binding, role, found, err := ResolvePrimaryEmailTx(tx, a.database, o.Email)
	if err != nil {
		return s, d.ErrUnavailable
	}
	if !found || binding.AuthID != o.AuthID || role != o.RoleRevision {
		return s, nil
	}
	revision, _, err := a.CredentialBoundsTx(tx, o.AuthID)
	if errors.Is(err, ap.ErrAuthenticationFailed) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if revision != o.AccountRevision {
		return s, nil
	}
	record, err := r.passwords.readPasswordTx(tx, o.AuthID)
	if err != nil {
		return s, d.ErrUnavailable
	}
	if record.Revision != o.PasswordRevision {
		return s, nil
	}
	s.Password = record
	s.Usable = true
	return s, nil
}
func (r *PasswordLoginRepository) ReadLogin(ctx context.Context, id string, now time.Time) (p.LoginSnapshot, error) {
	var out p.LoginSnapshot
	err := r.passwords.auth.WithAuthTransaction(ctx, func(tx context.Context) error {
		var err error
		out, err = r.bound(tx, id, r.passwords.auth.currentTime(now))
		return err
	})
	return out, passwordLoginError(err)
}
func (r *PasswordLoginRepository) FailLogin(ctx context.Context, id string, now time.Time) error {
	a := r.passwords.auth
	return passwordLoginError(a.WithAuthTransaction(ctx, func(tx context.Context) error {
		o, err := r.read(tx, bson.M{"operationId": id})
		if err != nil {
			return err
		}
		if o.Status != auth.Pending || o.KeyID != r.protocol.KeyID() || o.ServiceID != r.protocol.ServiceID() {
			return nil
		}
		status := auth.Pending
		if o.FailedAttempts+1 >= 5 || !a.currentTime(now).Before(o.ExpiresAt) {
			status = auth.Closed
		}
		_, err = a.database.Collection(PasswordLoginCollection).UpdateOne(tx, bson.M{"operationId": id, "status": auth.Pending, "failedAttempts": o.FailedAttempts}, bson.M{"$inc": bson.M{"failedAttempts": int64(1)}, "$set": bson.M{"status": status}})
		return err
	}))
}
func samePasswordLogin(a, b p.Login) bool {
	a.FailedAttempts = 0
	b.FailedAttempts = 0
	return reflect.DeepEqual(a, b)
}
func (r *PasswordLoginRepository) CompleteLogin(ctx context.Context, c p.LoginCommit, now time.Time) (string, error) {
	var credentialID string
	a := r.passwords.auth
	err := a.WithAuthTransaction(ctx, func(tx context.Context) error {
		observed := a.currentTime(now)
		s, err := r.bound(tx, c.Snapshot.Operation.OperationID, observed)
		if err != nil {
			return err
		}
		o := s.Operation
		if !s.Usable || !c.Snapshot.Usable || !samePasswordLogin(o, c.Snapshot.Operation) || s.Password.Revision != c.Snapshot.Password.Revision {
			return d.ErrAuthentication
		}
		if err = a.ConfirmAccountTx(tx, o.AuthID, o.AccountRevision); err != nil {
			return err
		}
		// Fence role ownership as well as the global Auth transaction generation.
		role, err := a.database.Collection(EmailDirectoryCollection).UpdateOne(tx, bson.M{"authId": o.AuthID, "loginRoleRevision": o.RoleRevision}, bson.M{"$inc": bson.M{"authenticationFence": int64(1)}})
		if err != nil {
			return err
		}
		if role.MatchedCount != 1 {
			return d.ErrAuthentication
		}
		var credential CredentialDocument
		err = a.database.Collection(CredentialCollection).FindOne(tx, bson.M{"fingerprint": o.Fingerprint}).Decode(&credential)
		if errors.Is(err, m.ErrNoDocuments) {
			v := c.Credential
			if v.AuthID != o.AuthID || v.CredentialRevision != o.AccountRevision || v.RevokedAt != nil || !bytes.Equal(v.PublicKey, o.PublicKey) || !bytes.Equal(v.Fingerprint, o.Fingerprint) || !validCredential(credentialDocument(v)) {
				return d.ErrAuthentication
			}
			if err = a.InsertCredentialTx(tx, v); err != nil {
				return err
			}
			credential = credentialDocument(v)
		} else if err != nil {
			return err
		}
		_, minimum, err := a.CredentialBoundsTx(tx, o.AuthID)
		if err != nil {
			return err
		}
		if !validCredential(credential) || credential.AuthID != o.AuthID || !bytes.Equal(credential.PublicKey, o.PublicKey) || !d.EligibleCredential(credential.CredentialRevision, minimum, o.AccountRevision) {
			return d.ErrAuthentication
		}
		session := c.Session
		session.CredentialID = credential.CredentialID
		if session.AuthID != o.AuthID || session.AccountRevision != o.AccountRevision || session.PasswordRevision != o.PasswordRevision || session.AuthenticationMethod != d.PasswordAndDevice || session.SourceSessionID != "" || session.EmailBindingRevision != 0 {
			return d.ErrAuthentication
		}
		if c.Upgrade.Valid() && reflect.DeepEqual(s.Password.Material, c.Snapshot.Password.Material) {
			u := c.Upgrade
			old := s.Password.Material
			if u.Parameters.MemoryKiB < old.Parameters.MemoryKiB || u.Parameters.Iterations < old.Parameters.Iterations {
				return d.ErrUnavailable
			}
			doc := passwordDoc(d.Record{AuthID: o.AuthID, Revision: s.Password.Revision, Material: u, ChangedAt: s.Password.ChangedAt})
			if _, err = a.database.Collection(PasswordCollection).ReplaceOne(tx, bson.M{"authId": o.AuthID, "passwordRevision": s.Password.Revision}, doc); err != nil {
				return err
			}
		}
		if err = a.CreateSessionTx(tx, session, observed); err != nil {
			return err
		}
		result, err := a.database.Collection(PasswordLoginCollection).UpdateOne(tx, bson.M{"operationId": o.OperationID, "status": auth.Pending, "failedAttempts": bson.M{"$lt": int64(5)}}, bson.M{"$set": bson.M{"status": auth.Completed}})
		if err != nil {
			return err
		}
		if result.MatchedCount != 1 {
			return d.ErrAuthentication
		}
		if _, err = a.database.Collection(PasswordAuditCollection).InsertOne(tx, bson.M{"operationId": o.OperationID, "authId": o.AuthID, "action": "PASSWORD_LOGIN", "authenticationMethod": d.PasswordAndDevice, "credentialId": credential.CredentialID, "sessionId": session.SessionID, "at": observed}); err != nil {
			return err
		}
		credentialID = credential.CredentialID
		return nil
	})
	return credentialID, passwordLoginError(err)
}
