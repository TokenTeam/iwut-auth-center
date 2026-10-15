package mongo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	auth "iwut-auth-center/internal/authentication/domain"
	authport "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/emailaccount/domain"
	p "iwut-auth-center/internal/emailaccount/port"
	emailbinding "iwut-auth-center/internal/emailbinding/domain"
	pwd "iwut-auth-center/internal/password/domain"
)

type EmailAccountRepository struct {
	registration *RegistrationRepository
	passwords    *PasswordRepository
	mailQuota    *EmailRepository
	keyID        string
}

func NewEmailAccountRepository(registration *RegistrationRepository, passwords *PasswordRepository, keyID string, limits EmailLimits) (*EmailAccountRepository, error) {
	if registration == nil || passwords == nil || len(keyID) != 64 {
		return nil, d.ErrUnavailable
	}
	quota, err := NewEmailRepository(registration, keyID, limits)
	if err != nil {
		return nil, err
	}
	return &EmailAccountRepository{registration, passwords, quota, keyID}, nil
}
func emailAccountError(err error) error {
	if errors.Is(err, authport.ErrSessionInvalid) || errors.Is(err, authport.ErrAuthenticationFailed) {
		return d.ErrSession
	}
	return err
}
func (r *EmailAccountRepository) Snapshot(ctx context.Context, digest []byte, password bool, now time.Time) (p.Snapshot, error) {
	var result p.Snapshot
	err := r.registration.WithAuthTransaction(ctx, func(tx context.Context) error {
		session, err := r.registration.CheckSessionReadTx(tx, digest, now)
		if err != nil {
			return emailAccountError(err)
		}
		directory, err := ReadEmailDirectoryTx(tx, r.registration.db, session.AuthID)
		if err != nil {
			return err
		}
		cur, err := r.registration.db.Collection(EmailAccountOperationCollection).Find(tx, bson.M{"authId": session.AuthID, "purpose": d.Add, "status": auth.Pending, "keyId": r.keyID, "accountRevision": session.AccountRevision, "directoryRevision": directory.Revision, "expiresAt": bson.M{"$gt": r.registration.currentTime(now)}, "failedAttempts": bson.M{"$lt": 5}}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: 1}, {Key: "operationId", Value: 1}}).SetLimit(4))
		if err != nil {
			return err
		}
		defer cur.Close(tx)
		for cur.Next(tx) {
			var raw bson.Raw
			if err = cur.Decode(&raw); err != nil {
				return err
			}
			op, err := decodeEmailAccountOperation(raw)
			if err != nil {
				return err
			}
			directory.Pending = append(directory.Pending, d.Pending{OperationID: op.OperationID, Email: op.Email, ExpiresAt: op.ExpiresAt, ResendAfter: op.ResendAfter})
		}
		if cur.Err() != nil {
			return cur.Err()
		}
		if len(directory.Pending) > 3 {
			return d.ErrUnavailable
		}
		result = p.Snapshot{Session: session, Directory: directory}
		if password {
			record, err := r.passwords.readPasswordTx(tx, session.AuthID)
			if err != nil {
				return err
			}
			result.Password = record
		}
		return nil
	})
	return result, err
}

type emailAccountOperationDocument struct {
	OperationID             string    `bson:"operationId"`
	RequestID               string    `bson:"requestId"`
	Purpose                 string    `bson:"purpose"`
	Actor                   string    `bson:"actor"`
	AuthID                  string    `bson:"authId"`
	Email                   string    `bson:"email"`
	ServiceID               string    `bson:"serviceId"`
	KeyID                   string    `bson:"keyId"`
	Status                  string    `bson:"status"`
	PublicKey               []byte    `bson:"publicKey"`
	Fingerprint             []byte    `bson:"fingerprint"`
	Challenge               []byte    `bson:"challenge"`
	RequestMAC              []byte    `bson:"requestMac"`
	CodeMAC                 []byte    `bson:"codeMac"`
	AccountRevision         int64     `bson:"accountRevision"`
	DirectoryRevision       int64     `bson:"directoryRevision"`
	FailedAttempts          int64     `bson:"failedAttempts"`
	CreatedAt               time.Time `bson:"createdAt"`
	ExpiresAt               time.Time `bson:"expiresAt"`
	ResendAfter             time.Time `bson:"resendAfter"`
	RetainUntil             time.Time `bson:"retainUntil"`
	ResultDirectoryRevision int64     `bson:"resultDirectoryRevision"`
	ResultRoleRevision      int64     `bson:"resultRoleRevision"`
}

func emailAccountOpDoc(o p.Operation) emailAccountOperationDocument {
	return emailAccountOperationDocument{o.OperationID, o.RequestID, o.Purpose, o.Actor, o.AuthID, o.Email, o.ServiceID, o.KeyID, o.Status, o.PublicKey, o.Fingerprint, o.Challenge, o.RequestMAC, o.CodeMAC, o.AccountRevision, o.DirectoryRevision, int64(o.FailedAttempts), o.CreatedAt, o.ExpiresAt, o.ResendAfter, o.RetainUntil, o.ResultDirectoryRevision, o.ResultRoleRevision}
}
func (o emailAccountOperationDocument) domain() p.Operation {
	return p.Operation{OperationID: o.OperationID, RequestID: o.RequestID, Purpose: o.Purpose, Actor: o.Actor, AuthID: o.AuthID, Email: o.Email, ServiceID: o.ServiceID, KeyID: o.KeyID, Status: o.Status, PublicKey: o.PublicKey, Fingerprint: o.Fingerprint, Challenge: o.Challenge, RequestMAC: o.RequestMAC, CodeMAC: o.CodeMAC, AccountRevision: o.AccountRevision, DirectoryRevision: o.DirectoryRevision, FailedAttempts: int(o.FailedAttempts), CreatedAt: o.CreatedAt, ExpiresAt: o.ExpiresAt, ResendAfter: o.ResendAfter, RetainUntil: o.RetainUntil, ResultDirectoryRevision: o.ResultDirectoryRevision, ResultRoleRevision: o.ResultRoleRevision}
}
func decodeEmailAccountOperation(raw bson.Raw) (p.Operation, error) {
	if !identityFields(raw, map[string]bson.Type{"operationId": bson.TypeString, "requestId": bson.TypeString, "purpose": bson.TypeString, "actor": bson.TypeString, "keyId": bson.TypeString, "email": bson.TypeString, "authId": bson.TypeString, "serviceId": bson.TypeString, "status": bson.TypeString, "requestMac": bson.TypeBinary, "codeMac": bson.TypeBinary, "accountRevision": bson.TypeInt64, "directoryRevision": bson.TypeInt64, "failedAttempts": bson.TypeInt64, "createdAt": bson.TypeDateTime, "expiresAt": bson.TypeDateTime, "resendAfter": bson.TypeDateTime, "retainUntil": bson.TypeDateTime, "resultDirectoryRevision": bson.TypeInt64, "resultRoleRevision": bson.TypeInt64}) {
		return p.Operation{}, d.ErrUnavailable
	}
	var doc emailAccountOperationDocument
	if bson.Unmarshal(raw, &doc) != nil {
		return p.Operation{}, d.ErrUnavailable
	}
	o := doc.domain()
	normalized, normalizeErr := emailbinding.NormalizeEmail(o.Email)
	device, deviceErr := deviceprotocol.New(o.ServiceID)
	key, keyErr := hex.DecodeString(o.KeyID)
	if normalizeErr != nil || normalized != o.Email || deviceErr != nil || keyErr != nil || len(key) != 32 || hex.EncodeToString(key) != o.KeyID || o.CreatedAt.UnixMilli() < 0 || !o.ResendAfter.Equal(o.CreatedAt.Add(time.Minute)) {
		return p.Operation{}, d.ErrUnavailable
	}
	if o.Status == auth.Completed {
		if o.AuthID == "" || o.ResultDirectoryRevision <= 0 || o.ResultRoleRevision <= 0 || o.ResultRoleRevision > o.ResultDirectoryRevision {
			return p.Operation{}, d.ErrUnavailable
		}
	} else if o.ResultDirectoryRevision != 0 || o.ResultRoleRevision != 0 {
		return p.Operation{}, d.ErrUnavailable
	}
	if !deviceprotocol.ValidID(o.OperationID) || !deviceprotocol.ValidID(o.RequestID) || o.Actor == "" || len(o.KeyID) != 64 || len(o.RequestMAC) != 32 || len(o.CodeMAC) != 32 || o.FailedAttempts < 0 || o.FailedAttempts > 5 || !o.ExpiresAt.Equal(o.CreatedAt.Add(10*time.Minute)) || !o.RetainUntil.Equal(o.CreatedAt.Add(24*time.Hour)) || (o.Status != auth.Pending && o.Status != auth.Completed && o.Status != auth.Closed) {
		return p.Operation{}, d.ErrUnavailable
	}
	if o.Purpose == d.Add {
		if o.AuthID == "" || o.AccountRevision <= 0 || o.DirectoryRevision <= 0 || o.Actor != o.AuthID {
			return p.Operation{}, d.ErrUnavailable
		}
	} else if o.Purpose == d.Register {
		if len(o.PublicKey) != 65 || len(o.Fingerprint) != 32 || len(o.Challenge) != 32 || o.Actor != hex.EncodeToString(o.Fingerprint) {
			return p.Operation{}, d.ErrUnavailable
		}
		fingerprint, err := device.Fingerprint(o.PublicKey)
		if err != nil || !bytes.Equal(fingerprint, o.Fingerprint) || o.AccountRevision != 0 || o.DirectoryRevision != 0 || (o.Status != auth.Completed && o.AuthID != "") {
			return p.Operation{}, d.ErrUnavailable
		}
	} else {
		return p.Operation{}, d.ErrUnavailable
	}
	return o, nil
}
func (r *EmailAccountRepository) Get(ctx context.Context, id string) (p.Operation, error) {
	var raw bson.Raw
	err := r.registration.db.Collection(EmailAccountOperationCollection).FindOne(ctx, bson.M{"operationId": id}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return p.Operation{}, d.ErrVerification
	}
	if err != nil {
		return p.Operation{}, err
	}
	return decodeEmailAccountOperation(raw)
}
func (r *EmailAccountRepository) capacityTx(ctx context.Context, now time.Time) error {
	err := sharedOperationCapacityTx(ctx, r.registration.db, now, min(10000, r.registration.maxPending), true)
	if errors.Is(err, authport.ErrLimitExceeded) {
		return d.ErrLimited
	}
	return err
}

func (r *EmailAccountRepository) Begin(ctx context.Context, candidate p.Operation, digest []byte, source string, now time.Time) (p.Operation, bool, error) {
	var result p.Operation
	fresh := false
	err := r.registration.WithAuthTransaction(ctx, func(tx context.Context) error {
		fresh = false
		observed := r.registration.currentTime(now)
		o := candidate
		if o.KeyID != r.keyID || o.Status != auth.Pending || !observed.Before(o.ExpiresAt) {
			return d.ErrVerification
		}
		if o.Purpose == d.Add {
			s, err := r.registration.CheckSessionReadTx(tx, digest, observed)
			if err != nil {
				return emailAccountError(err)
			}
			if s.AuthID != o.AuthID || s.AccountRevision != o.AccountRevision {
				return d.ErrSession
			}
			dir, err := ReadEmailDirectoryTx(tx, r.registration.db, s.AuthID)
			if err != nil {
				return err
			}
			if dir.Revision != o.DirectoryRevision {
				return d.ErrDirectoryConflict
			}
			if len(dir.Bindings) >= 10 {
				return d.ErrBindingLimit
			}
		} else if o.Purpose != d.Register || len(digest) != 0 {
			return d.ErrInvalid
		}
		var raw bson.Raw
		err := r.registration.db.Collection(EmailAccountOperationCollection).FindOne(tx, bson.M{"purpose": o.Purpose, "actor": o.Actor, "requestId": o.RequestID}).Decode(&raw)
		if err == nil {
			prior, err := decodeEmailAccountOperation(raw)
			if err != nil {
				return err
			}
			if !hmac.Equal(prior.RequestMAC, o.RequestMAC) {
				return d.ErrConflict
			}
			if prior.Status == auth.Completed && o.Purpose == d.Register {
				return d.ErrCompleted
			}
			if prior.Status != auth.Pending || prior.KeyID != r.keyID || !observed.Before(prior.ExpiresAt) || !observed.Before(prior.RetainUntil) {
				return d.ErrVerification
			}
			result = prior
			return nil
		}
		if !errors.Is(err, m.ErrNoDocuments) {
			return err
		}
		if err = r.capacityTx(tx, observed); err != nil {
			return err
		}
		if o.Purpose == d.Add {
			count, err := r.registration.db.Collection(EmailAccountOperationCollection).CountDocuments(tx, bson.M{"purpose": d.Add, "authId": o.AuthID, "accountRevision": o.AccountRevision, "directoryRevision": o.DirectoryRevision, "email": bson.M{"$ne": o.Email}, "status": auth.Pending, "keyId": r.keyID, "expiresAt": bson.M{"$gt": observed}}, options.Count().SetLimit(3))
			if err != nil {
				return err
			}
			if count >= 3 {
				return d.ErrLimited
			}
		}
		ownerKey := "owner:REGISTER:" + o.Actor
		if o.Purpose == d.Add {
			ownerKey = "owner:BIND:" + o.AuthID
		}
		for _, q := range []struct {
			key      string
			limit    int
			cooldown bool
		}{{"email:" + o.Email, r.mailQuota.limits.EmailHourly, true}, {"source:" + source, r.mailQuota.limits.SourceHourly, false}, {ownerKey, r.mailQuota.limits.OwnerHourly, true}} {
			if err = r.mailQuota.debitTx(tx, q.key, q.limit, q.cooldown, observed); err != nil {
				if errors.Is(err, emailbinding.ErrRate) {
					return d.ErrLimited
				}
				return err
			}
		}
		filter := bson.M{"purpose": o.Purpose, "actor": o.Actor, "status": auth.Pending, "expiresAt": bson.M{"$gt": observed}}
		if o.Purpose == d.Add {
			filter["email"] = o.Email
		}
		// Only a bounded number of live proposals is replaced. Retained history
		// is never scanned or rewritten as part of this Begin.
		cur, err := r.registration.db.Collection(EmailAccountOperationCollection).Find(tx, filter, options.Find().SetLimit(4).SetProjection(bson.M{"operationId": 1}))
		if err != nil {
			return err
		}
		var ids []bson.M
		if err = cur.All(tx, &ids); err != nil {
			return err
		}
		cur.Close(tx)
		for _, v := range ids {
			if _, err = r.registration.db.Collection(EmailAccountOperationCollection).UpdateOne(tx, bson.M{"operationId": v["operationId"], "status": auth.Pending}, bson.M{"$set": bson.M{"status": auth.Closed}}); err != nil {
				return err
			}
		}
		if _, err = r.registration.db.Collection(EmailAccountOperationCollection).InsertOne(tx, emailAccountOpDoc(o)); err != nil {
			return err
		}
		result = o
		fresh = true
		return nil
	})
	return result, fresh, err
}
func (r *EmailAccountRepository) Fail(ctx context.Context, id string, now time.Time) error {
	return r.registration.WithAuthTransaction(ctx, func(tx context.Context) error {
		o, err := r.Get(tx, id)
		if err != nil {
			return err
		}
		if o.Status != auth.Pending {
			return nil
		}
		update := bson.M{"$inc": bson.M{"failedAttempts": int64(1)}}
		if o.FailedAttempts >= 4 || !r.registration.currentTime(now).Before(o.ExpiresAt) {
			update["$set"] = bson.M{"status": auth.Closed}
		}
		_, err = r.registration.db.Collection(EmailAccountOperationCollection).UpdateOne(tx, bson.M{"operationId": id, "status": auth.Pending, "failedAttempts": bson.M{"$lt": int64(5)}}, update)
		return err
	})
}
func sameEmailAccountOperation(a, b p.Operation) bool {
	return a.OperationID == b.OperationID && a.Purpose == b.Purpose && a.Actor == b.Actor && a.AuthID == b.AuthID && a.Email == b.Email && a.KeyID == b.KeyID && a.ServiceID == b.ServiceID && a.AccountRevision == b.AccountRevision && a.DirectoryRevision == b.DirectoryRevision && a.ExpiresAt.Equal(b.ExpiresAt) && bytes.Equal(a.RequestMAC, b.RequestMAC) && bytes.Equal(a.CodeMAC, b.CodeMAC) && bytes.Equal(a.PublicKey, b.PublicKey) && bytes.Equal(a.Challenge, b.Challenge) && bytes.Equal(a.Fingerprint, b.Fingerprint)
}

func (r *EmailAccountRepository) Complete(ctx context.Context, expected p.Operation, digest []byte, registration *p.Registration, bindingID string, now time.Time) (d.Directory, error) {
	var result d.Directory
	err := r.registration.WithAuthTransaction(ctx, func(tx context.Context) error {
		observed := r.registration.currentTime(now)
		o, err := r.Get(tx, expected.OperationID)
		if err != nil {
			return err
		}
		if o.Status == auth.Completed && o.Purpose == d.Register {
			return d.ErrCompleted
		}
		if o.KeyID != r.keyID || !sameEmailAccountOperation(o, expected) || !observed.Before(o.RetainUntil) || o.FailedAttempts >= 5 {
			return d.ErrVerification
		}
		if o.Status == auth.Completed && o.Purpose == d.Add {
			s, err := r.registration.CheckSessionReadTx(tx, digest, observed)
			if err != nil {
				return emailAccountError(err)
			}
			if s.AuthID != o.AuthID || s.AccountRevision != o.AccountRevision {
				return d.ErrVerification
			}
			dir, err := ReadEmailDirectoryTx(tx, r.registration.db, o.AuthID)
			if err != nil {
				return err
			}
			if dir.Revision != o.ResultDirectoryRevision || dir.LoginRoleRevision != o.ResultRoleRevision {
				return d.ErrDirectoryConflict
			}
			result = dir
			return nil
		}
		if o.Status != auth.Pending || !observed.Before(o.ExpiresAt) || !deviceprotocol.ValidID(bindingID) {
			return d.ErrVerification
		}
		count, err := r.registration.db.Collection(EmailBindingCollection).CountDocuments(tx, bson.M{"email": o.Email}, options.Count().SetLimit(1))
		if err != nil {
			return err
		}
		if count != 0 {
			return d.ErrOccupied
		}
		owner := o.AuthID
		directoryRevision, roleRevision := int64(1), int64(1)
		if o.Purpose == d.Register {
			if registration == nil || len(digest) != 0 || !registration.Password.Valid() || registration.BindingID != bindingID || !bytes.Equal(registration.Commit.Credential.PublicKey, o.PublicKey) || !bytes.Equal(registration.Commit.Credential.Fingerprint, o.Fingerprint) || registration.Commit.Credential.CredentialRevision != 1 {
				return d.ErrVerification
			}
			owner = registration.Commit.Credential.AuthID
			if err = r.passwords.InitializePasswordTx(tx, pwd.Record{AuthID: owner, Revision: 1, Material: registration.Password, ChangedAt: observed}); err != nil {
				return err
			}
			if _, err = r.registration.db.Collection(EmailDirectoryCollection).InsertOne(tx, emailDirectoryDocument{AuthID: owner, LoginBindingID: bindingID, Revision: 1, LoginRoleRevision: 1, VerifiedCount: 1}); err != nil {
				return err
			}
		} else if o.Purpose == d.Add {
			if registration != nil {
				return d.ErrInvalid
			}
			s, err := r.registration.CheckSessionReadTx(tx, digest, observed)
			if err != nil {
				return emailAccountError(err)
			}
			if s.AuthID != owner || s.AccountRevision != o.AccountRevision {
				return d.ErrSession
			}
			dir, err := ReadEmailDirectoryTx(tx, r.registration.db, owner)
			if err != nil {
				return err
			}
			if dir.Revision != o.DirectoryRevision || dir.Revision == math.MaxInt64 {
				return d.ErrDirectoryConflict
			}
			if len(dir.Bindings) >= 10 {
				return d.ErrBindingLimit
			}
			directoryRevision = dir.Revision + 1
			roleRevision = dir.LoginRoleRevision
			updated, err := r.registration.db.Collection(EmailDirectoryCollection).UpdateOne(tx, bson.M{"authId": owner, "revision": dir.Revision}, bson.M{"$inc": bson.M{"revision": int64(1), "verifiedCount": int64(1)}})
			if err != nil {
				return err
			}
			if updated.MatchedCount != 1 {
				return d.ErrDirectoryConflict
			}
		} else {
			return d.ErrInvalid
		}
		if _, err = r.registration.db.Collection(EmailBindingCollection).InsertOne(tx, emailBindingDocument{BindingID: bindingID, AuthID: owner, Email: o.Email, VerifiedAt: observed}); m.IsDuplicateKeyError(err) {
			return d.ErrOccupied
		} else if err != nil {
			return err
		}
		if o.Purpose == d.Register {
			if err = r.registration.CreateRegisteredUserTx(tx, registration.Commit, observed); m.IsDuplicateKeyError(err) {
				return d.ErrCredential
			} else if err != nil {
				return err
			}
		}
		updated, err := r.registration.db.Collection(EmailAccountOperationCollection).UpdateOne(tx, bson.M{"operationId": o.OperationID, "status": auth.Pending, "failedAttempts": bson.M{"$lt": int64(5)}, "expiresAt": bson.M{"$gt": observed}}, bson.M{"$set": bson.M{"status": auth.Completed, "authId": owner, "resultDirectoryRevision": directoryRevision, "resultRoleRevision": roleRevision}})
		if err != nil {
			return err
		}
		if updated.MatchedCount != 1 {
			return d.ErrVerification
		}
		if _, err = r.registration.db.Collection(EmailAuditCollection).InsertOne(tx, bson.M{"operationId": o.OperationID, "authId": owner, "action": o.Purpose, "bindingId": bindingID, "directoryRevision": directoryRevision, "loginRoleRevision": roleRevision, "at": observed}); err != nil {
			return err
		}
		result, err = ReadEmailDirectoryTx(tx, r.registration.db, owner)
		return err
	})
	return result, err
}

type emailMutationDocument struct {
	AuthID                  string    `bson:"authId"`
	Purpose                 string    `bson:"purpose"`
	RequestID               string    `bson:"requestId"`
	OperationID             string    `bson:"operationId"`
	BindingID               string    `bson:"bindingId"`
	KeyID                   string    `bson:"keyId"`
	RequestMAC              []byte    `bson:"requestMac"`
	DirectoryRevision       int64     `bson:"directoryRevision"`
	RoleRevision            int64     `bson:"roleRevision"`
	PasswordRevision        int64     `bson:"passwordRevision"`
	AccountRevision         int64     `bson:"accountRevision"`
	ResultDirectoryRevision int64     `bson:"resultDirectoryRevision"`
	ResultRoleRevision      int64     `bson:"resultRoleRevision"`
	CreatedAt               time.Time `bson:"createdAt"`
	RetainUntil             time.Time `bson:"retainUntil"`
}

func mutationDoc(o p.Mutation) emailMutationDocument {
	return emailMutationDocument{AuthID: o.AuthID, Purpose: o.Purpose, RequestID: o.RequestID, OperationID: o.OperationID, BindingID: o.BindingID, KeyID: o.KeyID, RequestMAC: o.RequestMAC, DirectoryRevision: o.DirectoryRevision, RoleRevision: o.RoleRevision, PasswordRevision: o.PasswordRevision, AccountRevision: o.AccountRevision, CreatedAt: o.CreatedAt, RetainUntil: o.RetainUntil}
}
func (o emailMutationDocument) domain() p.Mutation {
	return p.Mutation{AuthID: o.AuthID, Purpose: o.Purpose, RequestID: o.RequestID, OperationID: o.OperationID, BindingID: o.BindingID, KeyID: o.KeyID, RequestMAC: o.RequestMAC, DirectoryRevision: o.DirectoryRevision, RoleRevision: o.RoleRevision, PasswordRevision: o.PasswordRevision, AccountRevision: o.AccountRevision, CreatedAt: o.CreatedAt, RetainUntil: o.RetainUntil}
}
func (r *EmailAccountRepository) mutationTx(ctx context.Context, owner, purpose, requestID string, now time.Time) (emailMutationDocument, bool, error) {
	var raw bson.Raw
	err := r.registration.db.Collection(EmailAccountMutationCollection).FindOne(ctx, bson.M{"authId": owner, "purpose": purpose, "requestId": requestID, "retainUntil": bson.M{"$gt": now}}).Decode(&raw)
	if errors.Is(err, m.ErrNoDocuments) {
		return emailMutationDocument{}, false, nil
	}
	if err != nil {
		return emailMutationDocument{}, false, err
	}
	if !identityFields(raw, map[string]bson.Type{"directoryRevision": bson.TypeInt64, "roleRevision": bson.TypeInt64, "passwordRevision": bson.TypeInt64, "accountRevision": bson.TypeInt64, "resultDirectoryRevision": bson.TypeInt64, "resultRoleRevision": bson.TypeInt64}) {
		return emailMutationDocument{}, false, d.ErrUnavailable
	}
	var o emailMutationDocument
	if bson.Unmarshal(raw, &o) != nil || o.AuthID != owner || o.Purpose != purpose || o.RequestID != requestID || !deviceprotocol.ValidID(o.OperationID) || !deviceprotocol.ValidID(o.BindingID) || len(o.RequestMAC) != 32 || o.AccountRevision <= 0 || o.DirectoryRevision <= 0 || o.ResultDirectoryRevision <= 0 || o.ResultRoleRevision <= 0 || !o.RetainUntil.Equal(o.CreatedAt.Add(24*time.Hour)) {
		return emailMutationDocument{}, false, d.ErrUnavailable
	}
	return o, true, nil
}
func (r *EmailAccountRepository) FindMutation(ctx context.Context, digest []byte, purpose, requestID string, now time.Time) (p.Mutation, bool, error) {
	var result p.Mutation
	found := false
	err := r.registration.WithAuthTransaction(ctx, func(tx context.Context) error {
		s, err := r.registration.CheckSessionReadTx(tx, digest, now)
		if err != nil {
			return emailAccountError(err)
		}
		o, exists, err := r.mutationTx(tx, s.AuthID, purpose, requestID, r.registration.currentTime(now))
		if err != nil {
			return err
		}
		result = o.domain()
		found = exists
		return nil
	})
	return result, found, err
}
func (r *EmailAccountRepository) Mutate(ctx context.Context, snapshot p.Snapshot, o p.Mutation, now time.Time) (d.Directory, error) {
	var result d.Directory
	err := r.registration.WithAuthTransaction(ctx, func(tx context.Context) error {
		expectedKey := r.keyID
		if o.Purpose == d.Switch {
			expectedKey = r.passwords.keyID
		}
		if o.KeyID != expectedKey {
			return d.ErrConflict
		}
		observed := r.registration.currentTime(now)
		s, err := r.registration.CheckSessionReadTx(tx, snapshot.Session.TokenDigest, observed)
		if err != nil {
			return emailAccountError(err)
		}
		if s.AuthID != o.AuthID || s.AccountRevision != o.AccountRevision || o.AuthID != snapshot.Directory.AuthID {
			return d.ErrSession
		}
		dir, err := ReadEmailDirectoryTx(tx, r.registration.db, o.AuthID)
		if err != nil {
			return err
		}
		prior, found, err := r.mutationTx(tx, o.AuthID, o.Purpose, o.RequestID, observed)
		if err != nil {
			return err
		}
		if found {
			if prior.KeyID != o.KeyID || !hmac.Equal(prior.RequestMAC, o.RequestMAC) {
				return d.ErrConflict
			}
			if prior.AccountRevision != s.AccountRevision || prior.ResultDirectoryRevision != dir.Revision || prior.ResultRoleRevision != dir.LoginRoleRevision {
				return d.ErrDirectoryConflict
			}
			if o.Purpose == d.Switch {
				record, err := r.passwords.readPasswordTx(tx, o.AuthID)
				if err != nil {
					return err
				}
				if record.Revision != prior.PasswordRevision {
					return pwd.ErrConflict
				}
			}
			result = dir
			return nil
		}
		if dir.Revision != o.DirectoryRevision || dir.Revision == math.MaxInt64 {
			return d.ErrDirectoryConflict
		}
		if o.Purpose == d.Switch {
			if dir.LoginRoleRevision != o.RoleRevision || dir.LoginRoleRevision == math.MaxInt64 {
				return d.ErrRoleConflict
			}
			record, err := r.passwords.readPasswordTx(tx, o.AuthID)
			if err != nil {
				return err
			}
			if record.Revision != o.PasswordRevision || record.Revision != snapshot.Password.Revision {
				return pwd.ErrConflict
			}
		} else if o.Purpose != d.Remove {
			return d.ErrInvalid
		}
		target := false
		for _, b := range dir.Bindings {
			if b.BindingID == o.BindingID {
				target = true
			}
		}
		if !target {
			return d.ErrBindingNotFound
		}
		if o.Purpose == d.Remove && o.BindingID == dir.LoginBindingID {
			return d.ErrLoginRemoval
		}
		if o.Purpose == d.Switch && o.BindingID != dir.LoginBindingID {
			updated, updateErr := r.registration.db.Collection(EmailDirectoryCollection).UpdateOne(tx, bson.M{"authId": o.AuthID, "revision": dir.Revision, "loginRoleRevision": dir.LoginRoleRevision}, bson.M{"$set": bson.M{"loginBindingId": o.BindingID}, "$inc": bson.M{"revision": int64(1), "loginRoleRevision": int64(1)}})
			if updateErr != nil {
				return updateErr
			}
			if updated.MatchedCount != 1 {
				return d.ErrDirectoryConflict
			}
			dir.Revision++
			dir.LoginRoleRevision++
		} else if o.Purpose == d.Remove {
			deleted, err := r.registration.db.Collection(EmailBindingCollection).DeleteOne(tx, bson.M{"authId": o.AuthID, "bindingId": o.BindingID})
			if err != nil {
				return err
			}
			if deleted.DeletedCount != 1 {
				return d.ErrBindingNotFound
			}
			updated, updateErr := r.registration.db.Collection(EmailDirectoryCollection).UpdateOne(tx, bson.M{"authId": o.AuthID, "revision": dir.Revision}, bson.M{"$inc": bson.M{"revision": int64(1), "verifiedCount": int64(-1)}})
			if updateErr != nil {
				return updateErr
			}
			if updated.MatchedCount != 1 {
				return d.ErrDirectoryConflict
			}
			dir.Revision++
		}
		if err = sharedOperationCapacityTx(tx, r.registration.db, observed, 10000, false); errors.Is(err, authport.ErrLimitExceeded) {
			return d.ErrLimited
		} else if err != nil {
			return err
		}
		doc := mutationDoc(o)
		doc.ResultDirectoryRevision = dir.Revision
		doc.ResultRoleRevision = dir.LoginRoleRevision
		if _, err = r.registration.db.Collection(EmailAccountMutationCollection).InsertOne(tx, doc); err != nil {
			return err
		}
		if _, err = r.registration.db.Collection(EmailAuditCollection).InsertOne(tx, bson.M{"operationId": o.OperationID, "authId": o.AuthID, "action": o.Purpose, "bindingId": o.BindingID, "directoryRevision": dir.Revision, "loginRoleRevision": dir.LoginRoleRevision, "at": observed}); err != nil {
			return err
		}
		result, err = ReadEmailDirectoryTx(tx, r.registration.db, o.AuthID)
		return err
	})
	return result, err
}

var _ p.Repository = (*EmailAccountRepository)(nil)
