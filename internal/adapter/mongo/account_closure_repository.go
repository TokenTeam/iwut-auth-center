package mongo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/accountclosure/domain"
	admin "iwut-auth-center/internal/administrator/domain"
	owner "iwut-auth-center/internal/ownerexit/domain"
	password "iwut-auth-center/internal/password/domain"
	"math"
	"slices"
	"time"
)

const (
	AccountClosureCollection      = "auth_account_closure_operations"
	AccountClosureTaskCollection  = "auth_account_closure_tasks"
	AccountClosureAuditCollection = "auth_account_closure_audit"
	CredentialTombstoneCollection = "auth_closed_credential_fingerprints"
)

type AccountClosureRepository struct{ auth *AuthenticationRepository }

func NewAccountClosureRepository(a *AuthenticationRepository) (*AccountClosureRepository, error) {
	if a == nil {
		return nil, d.ErrUnavailable
	}
	return &AccountClosureRepository{a}, nil
}
func EnsureAccountClosureSchema(ctx context.Context, db *m.Database) error {
	for collection, models := range map[string][]m.IndexModel{
		AccountClosureCollection:      {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true)}, {Keys: bson.D{{Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true).SetPartialFilterExpression(bson.M{"requestId": bson.M{"$type": "string"}})}, {Keys: bson.D{{Key: "authId", Value: 1}, {Key: "state", Value: 1}}}},
		AccountClosureTaskCollection:  {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true)}},
		AccountClosureAuditCollection: {{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true)}},
		CredentialTombstoneCollection: {{Keys: bson.D{{Key: "fingerprint", Value: 1}}, Options: options.Index().SetUnique(true)}},
	} {
		if _, e := db.Collection(collection).Indexes().CreateMany(ctx, models); e != nil {
			return e
		}
	}
	return nil
}
func (r *AccountClosureRepository) transaction(ctx context.Context, fn func(context.Context) error) error {
	var semantic error
	e := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error { semantic = fn(tx); return semantic })
	if e == nil {
		return nil
	}
	for _, known := range []error{d.ErrInvalid, d.ErrProof, d.ErrToken, d.ErrConflict, d.ErrRate} {
		if errors.Is(semantic, known) {
			return known
		}
	}
	return d.ErrUnavailable
}
func (r *AccountClosureRepository) read(ctx context.Context, id string) (d.Operation, error) {
	var doc closureOperationDocument
	raw, e := r.auth.database.Collection(AccountClosureCollection).FindOne(ctx, bson.M{"operationId": id}).Raw()
	if errors.Is(e, m.ErrNoDocuments) {
		return d.Operation{}, d.ErrToken
	}
	if e != nil {
		return d.Operation{}, e
	}
	if !identityFields(raw, map[string]bson.Type{"accountRevision": bson.TypeInt64, "passwordRevision": bson.TypeInt64, "developerRevision": bson.TypeInt64, "permissionRevision": bson.TypeInt64, "acceptable": bson.TypeBoolean, "ledgerConfirmed": bson.TypeBoolean, "localCleanupComplete": bson.TypeBoolean}) || bson.Unmarshal(raw, &doc) != nil {
		return d.Operation{}, d.ErrUnavailable
	}
	o := d.Operation(doc)
	if !owner.ValidOperationID(o.OperationID) || len(o.Challenge) != 32 || o.PolicyVersion != d.PolicyVersion || o.ExpiresAt.Sub(o.CreatedAt) != 5*time.Minute {
		return o, d.ErrUnavailable
	}
	if o.FailedAttempts < 0 || o.FailedAttempts > 5 || !slices.Contains([]string{d.Preparing, d.Ready, d.Cancelled, d.TerminationPending, d.Terminated, d.CleanupComplete}, o.State) {
		return o, d.ErrUnavailable
	}
	if o.Acceptable && (!owner.ValidAuthID(o.AuthID) || o.AccountRevision <= 0) {
		return o, d.ErrUnavailable
	}
	if o.PasswordRevision < 0 || ((o.State == d.Ready || o.TerminatedAt != nil) && o.PasswordRevision == 0) {
		return o, d.ErrUnavailable
	}
	return o, nil
}
func (r *AccountClosureRepository) Read(ctx context.Context, id string) (d.Operation, error) {
	var o d.Operation
	e := r.transaction(ctx, func(tx context.Context) error { var e error; o, e = r.read(tx, id); return e })
	return o, e
}
func (r *AccountClosureRepository) save(ctx context.Context, o d.Operation) error {
	_, e := r.auth.database.Collection(AccountClosureCollection).ReplaceOne(ctx, bson.M{"operationId": o.OperationID}, closureOperationDocument(o))
	return e
}
func (r *AccountClosureRepository) Begin(ctx context.Context, o d.Operation) (d.Operation, error) {
	var out d.Operation
	e := r.transaction(ctx, func(tx context.Context) error {
		_, e := r.auth.database.Collection(AccountClosureCollection).UpdateMany(tx, bson.M{"requestId": o.RequestID, "createdAt": bson.M{"$lte": o.CreatedAt.Add(-24 * time.Hour)}}, bson.M{"$unset": bson.M{"requestId": ""}})
		if e != nil {
			return e
		}
		var old closureOperationDocument
		e = r.auth.database.Collection(AccountClosureCollection).FindOne(tx, bson.M{"requestId": o.RequestID}).Decode(&old)
		if e == nil {
			previous, err := r.read(tx, old.OperationID)
			if err != nil {
				return err
			}
			if previous.LocatorKind != o.LocatorKind || !bytes.Equal(previous.LocatorValue, o.LocatorValue) {
				return d.ErrConflict
			}
			out = previous
			return nil
		}
		if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		n, e := r.auth.database.Collection(AccountClosureCollection).CountDocuments(tx, bson.M{"expiresAt": bson.M{"$gt": o.CreatedAt}, "state": bson.M{"$in": bson.A{d.Preparing, d.Ready}}})
		if e != nil {
			return e
		}
		if n >= int64(r.auth.maxPending) {
			return d.ErrRate
		}
		out = o
		query := bson.M{"revokedAt": nil}
		if o.LocatorKind == "CREDENTIAL_ID" {
			query["credentialId"] = string(o.LocatorValue)
		} else {
			query["fingerprint"] = o.LocatorValue
		}
		var c CredentialDocument
		credentialRaw, err := r.auth.database.Collection(CredentialCollection).FindOne(tx, query).Raw()
		e = err
		if e == nil {
			if !identityFields(credentialRaw, map[string]bson.Type{"credentialRevision": bson.TypeInt64}) || bson.Unmarshal(credentialRaw, &c) != nil || !validCredential(c) {
				return d.ErrUnavailable
			}
			var raw bson.Raw
			e = r.auth.database.Collection(PrincipalCollection).FindOne(tx, bson.M{"authId": c.AuthID}).Decode(&raw)
			if e == nil {
				state := raw.Lookup("accountStatus")
				if state.Type == bson.TypeString && (state.StringValue() == "ACTIVE" || state.StringValue() == "DISABLED") {
					if !identityFields(raw, map[string]bson.Type{"principalType": bson.TypeString, "accountRevision": bson.TypeInt64, "minimumCredentialRevision": bson.TypeInt64}) {
						return d.ErrUnavailable
					}
					if raw.Lookup("principalType").StringValue() == "USER" {
						out.AuthID = c.AuthID
						out.CredentialID = c.CredentialID
						out.PublicKey = c.PublicKey
						out.AccountRevision = raw.Lookup("accountRevision").Int64()
						minimum := raw.Lookup("minimumCredentialRevision").Int64()
						if out.AccountRevision <= 0 || minimum <= 0 || minimum > out.AccountRevision || c.CredentialRevision > out.AccountRevision {
							return d.ErrUnavailable
						}
						out.Acceptable = password.EligibleCredential(c.CredentialRevision, minimum, out.AccountRevision)
					}
				}
			} else if !errors.Is(e, m.ErrNoDocuments) {
				return e
			}
		} else if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		_, e = r.auth.database.Collection(AccountClosureCollection).InsertOne(tx, closureOperationDocument(out))
		return e
	})
	return out, e
}
func (r *AccountClosureRepository) FailProof(ctx context.Context, id string, now time.Time) error {
	return r.transaction(ctx, func(tx context.Context) error {
		_, e := r.auth.database.Collection(AccountClosureCollection).UpdateOne(tx, bson.M{"operationId": id, "failedAttempts": bson.M{"$lt": 5}, "terminatedAt": bson.M{"$exists": false}}, bson.M{"$inc": bson.M{"failedAttempts": 1}})
		return e
	})
}

// snapshot joins every current closure-relevant version. Credential/email state
// is hashed deterministically so a change on another device invalidates preview.
func (r *AccountClosureRepository) snapshot(ctx context.Context, o d.Operation) (d.Operation, string, error) {
	var raw bson.Raw
	e := r.auth.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": o.AuthID}).Decode(&raw)
	if errors.Is(e, m.ErrNoDocuments) {
		return o, "", d.ErrProof
	}
	if e != nil {
		return o, "", e
	}
	if raw.Lookup("accountStatus").Type == bson.TypeString && raw.Lookup("accountStatus").StringValue() == "CLOSED" {
		return o, "", d.ErrProof
	}
	if !identityFields(raw, map[string]bson.Type{"principalType": bson.TypeString, "accountStatus": bson.TypeString, "accountRevision": bson.TypeInt64, "developerRevision": bson.TypeInt64, "permissionRevision": bson.TypeInt64, "permissions": bson.TypeArray}) {
		return o, "", d.ErrUnavailable
	}
	if !validDeveloperLifecycle(raw) {
		return o, "", d.ErrUnavailable
	}
	state := raw.Lookup("accountStatus").StringValue()
	if raw.Lookup("principalType").StringValue() != "USER" || (state != "ACTIVE" && state != "DISABLED") || raw.Lookup("accountRevision").Int64() != o.AccountRevision {
		return o, "", d.ErrProof
	}
	if o.AccountRevision == math.MaxInt64 {
		return o, "", d.ErrConflict
	}
	var c CredentialDocument
	credentialRaw, err := r.auth.database.Collection(CredentialCollection).FindOne(ctx, bson.M{"credentialId": o.CredentialID, "authId": o.AuthID, "revokedAt": nil}).Raw()
	e = err
	if errors.Is(e, m.ErrNoDocuments) {
		return o, "", d.ErrProof
	}
	if e != nil {
		return o, "", e
	}
	if !identityFields(credentialRaw, map[string]bson.Type{"credentialRevision": bson.TypeInt64}) || bson.Unmarshal(credentialRaw, &c) != nil || !validCredential(c) {
		return o, "", d.ErrUnavailable
	}
	minimum := raw.Lookup("minimumCredentialRevision")
	if minimum.Type != bson.TypeInt64 {
		return o, "", d.ErrUnavailable
	}
	if minimum.Int64() <= 0 || minimum.Int64() > o.AccountRevision || c.CredentialRevision > o.AccountRevision {
		return o, "", d.ErrUnavailable
	}
	if !password.EligibleCredential(c.CredentialRevision, minimum.Int64(), o.AccountRevision) || !bytes.Equal(c.PublicKey, o.PublicKey) {
		return o, "", d.ErrProof
	}
	// Argon verification is performed outside transaction retries. This strict
	// revision read binds its private attestation to the final Auth decision.
	passwordRecord, e := (&PasswordRepository{auth: r.auth}).readPasswordTx(ctx, o.AuthID)
	if e != nil {
		return o, "", d.ErrUnavailable
	}
	if o.PasswordRevision > 0 && o.PasswordRevision != passwordRecord.Revision {
		return o, "", d.ErrProof
	}
	o.PasswordRevision = passwordRecord.Revision
	o.DeveloperRevision = raw.Lookup("developerRevision").Int64()
	o.PermissionRevision = raw.Lookup("permissionRevision").Int64()
	if o.DeveloperRevision < 0 || o.PermissionRevision <= 0 {
		return o, "", d.ErrUnavailable
	}
	permissions, e := adminPermissions(raw.Lookup("permissions"))
	if e != nil {
		return o, "", e
	}
	blocker := ""
	for _, p := range permissions {
		if slices.Contains(admin.Permissions(), p) {
			blocker = d.AdminBlocker
		}
	}
	v := raw.Lookup("developerStatus")
	if v.Type != bson.TypeNull && v.Type != bson.TypeString {
		return o, "", d.ErrUnavailable
	}
	if v.Type == bson.TypeString {
		status := v.StringValue()
		if !slices.Contains([]string{"PENDING", "APPROVED", "REJECTED", "SUSPENDED", "WITHDRAWN"}, status) {
			return o, "", d.ErrUnavailable
		}
		if state == "ACTIVE" && status == "APPROVED" && blocker == "" {
			blocker = d.DeveloperBlocker
		}
	}
	o.DeveloperHandle = ""
	var handle bson.Raw
	e = r.auth.database.Collection(DeveloperHandleCollection).FindOne(ctx, bson.M{"authId": o.AuthID}).Decode(&handle)
	if e == nil {
		if !validHandleDocument(handle) && !validTerminalHandleDocument(handle) {
			return o, "", d.ErrUnavailable
		}
		o.DeveloperHandle = handle.Lookup("developerHandle").StringValue()
	} else if !errors.Is(e, m.ErrNoDocuments) {
		return o, "", e
	} else if v.Type == bson.TypeString && v.StringValue() == "WITHDRAWN" {
		return o, "", d.ErrUnavailable
	}
	if pv := raw.Lookup("developerHandle"); pv.Type != 0 && (pv.Type != bson.TypeString || pv.StringValue() != o.DeveloperHandle) {
		return o, "", d.ErrUnavailable
	}
	hash := sha256.New()
	cur, e := r.auth.database.Collection(CredentialCollection).Find(ctx, bson.M{"authId": o.AuthID}, options.Find().SetSort(bson.D{{Key: "credentialId", Value: 1}}).SetProjection(bson.M{"_id": 0, "credentialId": 1, "fingerprint": 1, "revokedAt": 1}))
	if e != nil {
		return o, "", e
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		hash.Write(cur.Current)
	}
	if e = cur.Err(); e != nil {
		return o, "", e
	}
	// Hash every bounded email binding and the separate login-role directory.
	bindings, err := r.auth.database.Collection(EmailBindingCollection).Find(ctx, bson.M{"authId": o.AuthID}, options.Find().SetSort(bson.D{{Key: "bindingId", Value: 1}}).SetProjection(bson.M{"_id": 0}).SetLimit(11))
	if err != nil {
		return o, "", err
	}
	defer bindings.Close(ctx)
	count := 0
	for bindings.Next(ctx) {
		count++
		if count > 10 {
			return o, "", d.ErrUnavailable
		}
		hash.Write(bindings.Current)
	}
	if err = bindings.Err(); err != nil {
		return o, "", err
	}
	directory, err := r.auth.database.Collection(EmailDirectoryCollection).FindOne(ctx, bson.M{"authId": o.AuthID}, options.FindOne().SetProjection(bson.M{"_id": 0})).Raw()
	if err == nil {
		hash.Write(directory)
	} else if !errors.Is(err, m.ErrNoDocuments) {
		return o, "", err
	}

	o.MutationDigest = hash.Sum(nil)
	return o, blocker, nil
}
func (r *AccountClosureRepository) cancelTx(tx context.Context, o *d.Operation, now time.Time, reason string) error {
	owned, e := r.auth.ReadOwnerExitTx(tx, o.AuthID, o.OperationID)
	if e == nil && owned.Decision == owner.Committed {
		return d.ErrConflict
	}
	if e == nil && owned.Decision == owner.Pending {
		_, e = r.auth.DecideOwnerExitTx(tx, o.AuthID, o.OperationID, owner.Cancelled, reason, now)
	}
	if e != nil && !errors.Is(e, owner.ErrNotFound) {
		return e
	}
	o.State = d.Cancelled
	return r.save(tx, *o)
}
func (r *AccountClosureRepository) Prepare(ctx context.Context, id string, passwordRevision int64, now time.Time) (d.Operation, owner.Operation, error) {
	var out d.Operation
	var owned owner.Operation
	var after error
	e := r.transaction(ctx, func(tx context.Context) error {
		after = nil
		owned = owner.Operation{}
		var e error
		out, e = r.read(tx, id)
		if e != nil {
			return e
		}
		if passwordRevision <= 0 || !out.Acceptable || out.FailedAttempts >= 5 || !now.Before(out.ExpiresAt) {
			return d.ErrProof
		}
		if out.State != d.Preparing {
			return d.ErrConflict
		}
		current, blocker, e := r.snapshot(tx, out)
		if e != nil {
			if errors.Is(e, d.ErrProof) {
				after = d.ErrProof
				return r.cancelTx(tx, &out, now, "CONDITIONS_CHANGED")
			}
			return e
		}
		if current.PasswordRevision != passwordRevision {
			after = d.ErrProof
			return r.cancelTx(tx, &out, now, "CONDITIONS_CHANGED")
		}
		if len(out.MutationDigest) > 0 && !sameSnapshot(out, current) {
			after = d.ErrProof
			return r.cancelTx(tx, &out, now, "CONDITIONS_CHANGED")
		}
		out = current
		out.Blocker = ""
		if blocker != "" {
			out.Blocker = blocker
			return r.cancelTx(tx, &out, now, "BLOCKED")
		}
		// Only a freshly verified device proof reaches here. Cancel older closure
		// preparations, then wait for App's cancellation receipt before proceeding.
		cur, e := r.auth.database.Collection(OwnerExitCollection).Find(tx, bson.M{"authId": out.AuthID, "operationId": bson.M{"$ne": id}, "$or": bson.A{bson.M{"decision": owner.Pending}, bson.M{"decision": owner.Cancelled, "appAcknowledged": false}}})
		if e != nil {
			return e
		}
		defer cur.Close(tx)
		waiting := false
		for cur.Next(tx) {
			var prior owner.Operation
			if cur.Decode(&prior) != nil || !prior.Valid() {
				return d.ErrUnavailable
			}
			if prior.Purpose == owner.Withdrawal && prior.Decision == owner.Pending {
				out.Blocker = d.LifecycleBlocker
				return r.save(tx, out)
			}
			if prior.Decision == owner.Pending {
				if _, e = r.auth.DecideOwnerExitTx(tx, out.AuthID, prior.OperationID, owner.Cancelled, "SUPERSEDED_AFTER_PROOF", now); e != nil {
					return e
				}
				_, e = r.auth.database.Collection(AccountClosureCollection).UpdateOne(tx, bson.M{"operationId": prior.OperationID, "terminatedAt": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"state": d.Cancelled}})
				if e != nil {
					return e
				}
			}
			waiting = true
		}
		if e = cur.Err(); e != nil {
			return e
		}
		if waiting {
			return r.save(tx, out)
		}
		owned, e = r.auth.CreateOwnerExitTx(tx, owner.Operation{OperationID: id, AuthID: out.AuthID, Purpose: owner.Closure, Decision: owner.Pending, AccountRevision: out.AccountRevision, DeveloperRevision: out.DeveloperRevision, PermissionRevision: out.PermissionRevision, CreatedAt: out.CreatedAt, ExpiresAt: out.ExpiresAt, NextAttemptAt: now})
		if e != nil {
			return e
		}
		if owned.Decision != owner.Pending {
			return d.ErrConflict
		}
		return r.save(tx, out)
	})
	if e == nil {
		e = after
	}
	return out, owned, e
}
func sameSnapshot(a, b d.Operation) bool {
	return a.AccountRevision == b.AccountRevision && a.PasswordRevision == b.PasswordRevision && a.DeveloperRevision == b.DeveloperRevision && a.PermissionRevision == b.PermissionRevision && bytes.Equal(a.MutationDigest, b.MutationDigest)
}
func (r *AccountClosureRepository) Ready(ctx context.Context, id string, confirmation, receipt []byte, now time.Time) (d.Operation, error) {
	var out d.Operation
	var after error
	e := r.transaction(ctx, func(tx context.Context) error {
		after = nil
		var e error
		out, e = r.read(tx, id)
		if e != nil {
			return e
		}
		if out.State != d.Preparing || out.PasswordRevision <= 0 || len(out.ConfirmationDigest) != 0 || !now.Before(out.ExpiresAt) {
			return d.ErrConflict
		}
		current, blocker, e := r.snapshot(tx, out)
		if e != nil || blocker != "" || !sameSnapshot(out, current) {
			if e != nil && !errors.Is(e, d.ErrProof) {
				return e
			}
			after = d.ErrConflict
			return r.cancelTx(tx, &out, now, "CONDITIONS_CHANGED")
		}
		owned, e := r.auth.ReadOwnerExitTx(tx, out.AuthID, id)
		if e != nil {
			return e
		}
		if owned.Decision != owner.Pending || owned.ReceiptID == "" {
			return d.ErrConflict
		}
		out.State = d.Ready
		out.ConfirmationDigest = confirmation
		out.ReceiptDigest = receipt
		return r.save(tx, out)
	})
	if e == nil {
		e = after
	}
	return out, e
}
func (r *AccountClosureRepository) Confirm(ctx context.Context, id string, digest []byte, now time.Time) (d.Operation, error) {
	var out d.Operation
	var after error
	e := r.transaction(ctx, func(tx context.Context) error {
		after = nil
		var e error
		out, e = r.read(tx, id)
		if e != nil {
			return e
		}
		if len(digest) != 32 || !bytes.Equal(out.ConfirmationDigest, digest) || !now.Before(out.RetainUntil) {
			return d.ErrToken
		}
		if out.TerminatedAt != nil {
			return nil
		}
		if out.State != d.Ready {
			return d.ErrConflict
		}
		current, blocker, e := r.snapshot(tx, out)
		if e != nil && !errors.Is(e, d.ErrProof) {
			return e
		}
		if e != nil || blocker != "" || !sameSnapshot(out, current) || !now.Before(out.ExpiresAt) {
			after = d.ErrConflict
			return r.cancelTx(tx, &out, now, "CONDITIONS_CHANGED")
		}
		owned, e := r.auth.ReadOwnerExitTx(tx, out.AuthID, id)
		if e != nil {
			return e
		}
		if owned.Decision != owner.Pending || owned.ReceiptID == "" {
			return d.ErrConflict
		}
		if _, e = r.auth.DecideOwnerExitTx(tx, out.AuthID, id, owner.Committed, "", now); e != nil {
			return e
		}
		out.TerminatedAt = &now
		out.State = d.TerminationPending
		out.RetainUntil = now.Add(30 * 24 * time.Hour)
		if e = r.writeTerminalTx(tx, out.Termination()); e != nil {
			return e
		}
		if e = r.save(tx, out); e != nil {
			return e
		}
		_, e = r.auth.database.Collection(AccountClosureAuditCollection).InsertOne(tx, bson.M{"operationId": id, "subjectAuthId": out.AuthID, "authenticationMethod": "DEVICE_PROOF", "credentialId": out.CredentialID, "policyVersion": d.PolicyVersion, "occurredAt": now, "accountRevision": out.AccountRevision + 1})
		return e
	})
	if e == nil {
		e = after
	}
	return out, e
}
func (r *AccountClosureRepository) writeTerminalTx(ctx context.Context, t d.Termination) error {
	// Replacement, not $set: the documented tombstone is the complete allowed shape.
	_, e := r.auth.database.Collection(PrincipalCollection).ReplaceOne(ctx, bson.M{"authId": t.AuthID}, bson.M{"authId": t.AuthID, "principalType": "USER", "accountStatus": "CLOSED", "accountRevision": t.AccountRevision, "terminatedAt": t.TerminatedAt, "closureOperationId": t.OperationID}, options.Replace().SetUpsert(true))
	if e != nil {
		return e
	}
	_, e = r.auth.database.Collection(AccountClosureTaskCollection).UpdateOne(ctx, bson.M{"operationId": t.OperationID}, bson.M{"$setOnInsert": bson.M{"authId": t.AuthID, "accountRevision": t.AccountRevision, "terminatedAt": t.TerminatedAt, "ledgerConfirmed": false, "step": 0, "localComplete": false, "appComplete": false, "nextAttemptAt": t.TerminatedAt}}, options.UpdateOne().SetUpsert(true))
	return e
}
func (r *AccountClosureRepository) Cancel(ctx context.Context, id string, digest []byte, now time.Time) (d.Operation, error) {
	var out d.Operation
	e := r.transaction(ctx, func(tx context.Context) error {
		var e error
		out, e = r.read(tx, id)
		if e != nil {
			return e
		}
		if len(digest) != 32 || !bytes.Equal(digest, out.ConfirmationDigest) || !now.Before(out.RetainUntil) {
			return d.ErrToken
		}
		if out.TerminatedAt != nil {
			return d.ErrConflict
		}
		return r.cancelTx(tx, &out, now, "USER_CANCELLED")
	})
	return out, e
}
func (r *AccountClosureRepository) Receipt(ctx context.Context, id string, digest []byte, now time.Time) (d.Operation, error) {
	var out d.Operation
	e := r.transaction(ctx, func(tx context.Context) error {
		var e error
		out, e = r.read(tx, id)
		if e != nil {
			return e
		}
		if len(digest) != 32 || !bytes.Equal(digest, out.ReceiptDigest) || !now.Before(out.RetainUntil) {
			return d.ErrToken
		}
		if out.TerminatedAt == nil {
			owned, e := r.auth.ReadOwnerExitTx(tx, out.AuthID, id)
			if e == nil && owned.Decision == owner.Cancelled {
				out.State = d.Cancelled
			} else if e != nil {
				return e
			}
		}
		return nil
	})
	return out, e
}
