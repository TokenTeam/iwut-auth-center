package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/ownerexit/domain"
	"math"
	"math/rand/v2"
	"time"
)

const OwnerExitCollection = "auth_account_owner_exit_operations"
const OwnerExitRequestCollection = "auth_account_owner_exit_requests"

type OwnerExitRepository struct{ auth *AuthenticationRepository }

func NewOwnerExitRepository(a *AuthenticationRepository) *OwnerExitRepository {
	return &OwnerExitRepository{a}
}
func EnsureOwnerExitSchema(ctx context.Context, db *m.Database) error {
	_, e := db.Collection(OwnerExitCollection).Indexes().CreateMany(ctx, []m.IndexModel{
		{Keys: bson.D{{Key: "operationId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("owner_exit_operation_unique")},
		{Keys: bson.D{{Key: "authId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("owner_exit_pending_subject_unique").SetPartialFilterExpression(bson.M{"decision": d.Pending})},
		{Keys: bson.D{{Key: "nextAttemptAt", Value: 1}, {Key: "operationId", Value: 1}}, Options: options.Index().SetName("owner_exit_delivery_due")},
	})
	if e != nil {
		return e
	}
	_, e = db.Collection(OwnerExitRequestCollection).Indexes().CreateOne(ctx, m.IndexModel{Keys: bson.D{{Key: "authId", Value: 1}, {Key: "requestId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("owner_exit_request_unique")})
	return e
}
func (a *AuthenticationRepository) ReadOwnerExitTx(ctx context.Context, authID, id string) (d.Operation, error) {
	var raw bson.Raw
	e := a.database.Collection(OwnerExitCollection).FindOne(ctx, bson.M{"authId": authID, "operationId": id}).Decode(&raw)
	if errors.Is(e, m.ErrNoDocuments) {
		return d.Operation{}, d.ErrNotFound
	}
	if e != nil {
		return d.Operation{}, e
	}
	// A durable closure is known but its App receipt is outside this restored
	// snapshot. Neither callbacks nor the ordinary expiry worker may guess CANCELLED.
	if marker := raw.Lookup("recoveryReceiptRequired"); marker.Type != 0 {
		if marker.Type != bson.TypeBoolean || marker.Boolean() {
			return d.Operation{}, d.ErrUnavailable
		}
	}
	if !identityFields(raw, map[string]bson.Type{"accountRevision": bson.TypeInt64, "developerRevision": bson.TypeInt64, "permissionRevision": bson.TypeInt64, "attempts": bson.TypeInt64, "notificationPending": bson.TypeBoolean, "appAcknowledged": bson.TypeBoolean}) {
		return d.Operation{}, d.ErrUnavailable
	}
	var op d.Operation
	if bson.Unmarshal(raw, &op) != nil || !op.Valid() {
		return d.Operation{}, d.ErrUnavailable
	}
	return op, nil
}
func (a *AuthenticationRepository) CreateOwnerExitTx(ctx context.Context, op d.Operation) (d.Operation, error) {
	if !op.Valid() || op.Decision != d.Pending || op.ReceiptID != "" || op.Attempts != 0 || op.NotificationPending || op.AppAcknowledged {
		return d.Operation{}, d.ErrInvalid
	}
	if op.RequestID != "" {
		if !d.ValidOperationID(op.RequestID) {
			return d.Operation{}, d.ErrInvalid
		}
		if _, e := a.database.Collection(OwnerExitRequestCollection).DeleteMany(ctx, bson.M{"authId": op.AuthID, "requestId": op.RequestID, "expiresAt": bson.M{"$lte": op.CreatedAt}}); e != nil {
			return d.Operation{}, e
		}
		var previous struct {
			OperationID string `bson:"operationId"`
		}
		err := a.database.Collection(OwnerExitRequestCollection).FindOne(ctx, bson.M{"authId": op.AuthID, "requestId": op.RequestID}).Decode(&previous)
		if err == nil {
			saved, e := a.ReadOwnerExitTx(ctx, op.AuthID, previous.OperationID)
			if e != nil {
				return saved, e
			}
			if saved.Purpose != op.Purpose || saved.DeveloperRevision != op.DeveloperRevision {
				return d.Operation{}, d.ErrConflict
			}
			return saved, nil
		}
		if !errors.Is(err, m.ErrNoDocuments) {
			return d.Operation{}, err
		}
	}
	if old, e := a.ReadOwnerExitTx(ctx, op.AuthID, op.OperationID); e == nil {
		if old.Purpose != op.Purpose || old.AccountRevision != op.AccountRevision || old.DeveloperRevision != op.DeveloperRevision || old.PermissionRevision != op.PermissionRevision {
			return d.Operation{}, d.ErrConflict
		}
		return old, nil
	} else if !errors.Is(e, d.ErrNotFound) {
		return d.Operation{}, e
	}
	count, e := a.database.Collection(OwnerExitCollection).CountDocuments(ctx, bson.M{"authId": op.AuthID, "decision": d.Pending})
	if e != nil {
		return d.Operation{}, e
	}
	if count != 0 {
		return d.Operation{}, d.ErrConflict
	}
	_, e = a.database.Collection(OwnerExitCollection).InsertOne(ctx, op)
	if m.IsDuplicateKeyError(e) {
		return d.Operation{}, d.ErrConflict
	}
	if e == nil && op.RequestID != "" {
		_, e = a.database.Collection(OwnerExitRequestCollection).InsertOne(ctx, bson.M{"authId": op.AuthID, "requestId": op.RequestID, "operationId": op.OperationID, "expiresAt": op.CreatedAt.Add(24 * time.Hour)})
	}
	return op, e
}
func (a *AuthenticationRepository) DecideOwnerExitTx(ctx context.Context, authID, id, decision, reason string, now time.Time) (d.Operation, error) {
	op, e := a.ReadOwnerExitTx(ctx, authID, id)
	if e != nil {
		return op, e
	}
	if decision != d.Committed && decision != d.Cancelled {
		return d.Operation{}, d.ErrInvalid
	}
	if op.Decision == decision {
		return op, nil
	}
	if op.Decision != d.Pending {
		return d.Operation{}, d.ErrConflict
	}
	if decision == d.Committed && (op.ReceiptID == "" || !now.Before(op.ExpiresAt)) {
		return d.Operation{}, d.ErrConflict
	}
	set := bson.M{"decision": decision, "decidedAt": now, "notificationPending": true, "nextAttemptAt": now}
	if decision == d.Cancelled {
		set["cancellationReason"] = reason
	}
	res, e := a.database.Collection(OwnerExitCollection).UpdateOne(ctx, bson.M{"authId": authID, "operationId": id, "decision": d.Pending}, bson.M{"$set": set})
	if e != nil {
		return d.Operation{}, e
	}
	if res.MatchedCount != 1 {
		return d.Operation{}, d.ErrConflict
	}
	return a.ReadOwnerExitTx(ctx, authID, id)
}
func (a *AuthenticationRepository) ownerExitCurrentTx(ctx context.Context, op d.Operation, now time.Time) (bool, error) {
	if !now.Before(op.ExpiresAt) {
		return false, nil
	}
	var raw bson.Raw
	e := a.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": op.AuthID}).Decode(&raw)
	if errors.Is(e, m.ErrNoDocuments) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	if !identityFields(raw, map[string]bson.Type{"principalType": bson.TypeString, "accountStatus": bson.TypeString, "accountRevision": bson.TypeInt64, "developerRevision": bson.TypeInt64, "permissionRevision": bson.TypeInt64}) {
		return false, d.ErrUnavailable
	}
	state := raw.Lookup("accountStatus").StringValue()
	if raw.Lookup("principalType").StringValue() != "USER" || (state != "ACTIVE" && state != "DISABLED") || op.Purpose == d.Withdrawal && state != "ACTIVE" || raw.Lookup("accountRevision").Int64() != op.AccountRevision || raw.Lookup("developerRevision").Int64() != op.DeveloperRevision || raw.Lookup("permissionRevision").Int64() != op.PermissionRevision {
		return false, nil
	}
	if op.Purpose == d.Withdrawal {
		if raw.Lookup("developerStatus").Type != bson.TypeString || raw.Lookup("developerStatus").StringValue() != "APPROVED" {
			return false, nil
		}
		var ss SessionDocument
		e = a.database.Collection(SessionCollection).FindOne(ctx, bson.M{"sessionId": op.SessionID, "authId": op.AuthID}).Decode(&ss)
		if errors.Is(e, m.ErrNoDocuments) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		_, e = a.CheckSessionReadTx(ctx, ss.TokenDigest, now)
		if errors.Is(e, ap.ErrSessionInvalid) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
	}
	return true, nil
}
func (a *AuthenticationRepository) BindOwnerExitPreparationTx(ctx context.Context, authID, id, receipt, blocker string, now time.Time) (d.Operation, error) {
	op, e := a.ReadOwnerExitTx(ctx, authID, id)
	if e != nil {
		return op, e
	}
	if op.Decision != d.Pending {
		return op, nil
	}
	if blocker != "" {
		if blocker != "OWNED_APPLICATIONS" && blocker != "PENDING_OWNERSHIP_CHANGE" || receipt != "" {
			return d.Operation{}, d.ErrInvalid
		}
		_, e = a.database.Collection(OwnerExitCollection).UpdateOne(ctx, bson.M{"operationId": id, "decision": d.Pending}, bson.M{"$set": bson.M{"blocker": blocker}})
		if e != nil {
			return d.Operation{}, e
		}
		return a.DecideOwnerExitTx(ctx, authID, id, d.Cancelled, "BLOCKED", now)
	}
	if !d.ValidReceiptID(receipt) || op.ReceiptID != "" && op.ReceiptID != receipt {
		return d.Operation{}, d.ErrConflict
	}
	current, e := a.ownerExitCurrentTx(ctx, op, now)
	if e != nil {
		return d.Operation{}, e
	}
	if !current {
		return a.DecideOwnerExitTx(ctx, authID, id, d.Cancelled, "CONDITIONS_CHANGED", now)
	}
	_, e = a.database.Collection(OwnerExitCollection).UpdateOne(ctx, bson.M{"authId": authID, "operationId": id, "decision": d.Pending}, bson.M{"$set": bson.M{"receiptId": receipt, "nextAttemptAt": now.Add(time.Second)}})
	if e != nil {
		return d.Operation{}, e
	}
	return a.ReadOwnerExitTx(ctx, authID, id)
}
func (r *OwnerExitRepository) transaction(ctx context.Context, fn func(context.Context) error) error {
	var cause error
	err := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error { cause = fn(tx); return cause })
	if err == nil {
		return nil
	}
	for _, e := range []error{d.ErrInvalid, d.ErrConflict, d.ErrNotFound} {
		if errors.Is(cause, e) {
			return e
		}
	}
	return d.ErrUnavailable
}
func (r *OwnerExitRepository) Get(ctx context.Context, authID, id string) (d.Operation, error) {
	var out d.Operation
	err := r.transaction(ctx, func(tx context.Context) error { var e error; out, e = r.auth.ReadOwnerExitTx(tx, authID, id); return e })
	return out, err
}
func (r *OwnerExitRepository) BindPreparation(ctx context.Context, authID, id string, p d.Preparation, now time.Time) (d.Operation, error) {
	var out d.Operation
	err := r.transaction(ctx, func(tx context.Context) error {
		var e error
		out, e = r.auth.BindOwnerExitPreparationTx(tx, authID, id, p.ReceiptID, p.Blocker, now)
		return e
	})
	return out, err
}
func (r *OwnerExitRepository) Due(ctx context.Context, now time.Time, limit int) ([]d.Operation, error) {
	if limit < 1 || limit > 100 {
		return nil, d.ErrInvalid
	}
	var out []d.Operation
	err := r.transaction(ctx, func(tx context.Context) error {
		out = nil
		cur, e := r.auth.database.Collection(OwnerExitCollection).Find(tx, bson.M{"recoveryReceiptRequired": bson.M{"$exists": false}, "nextAttemptAt": bson.M{"$lte": now}, "$or": bson.A{bson.M{"decision": d.Pending}, bson.M{"notificationPending": true}, bson.M{"decision": d.Committed, "appAcknowledged": false}}}, options.Find().SetLimit(int64(limit)).SetSort(bson.D{{Key: "nextAttemptAt", Value: 1}, {Key: "operationId", Value: 1}}))
		if e != nil {
			return e
		}
		defer cur.Close(tx)
		for cur.Next(tx) {
			var row d.Operation
			if cur.Decode(&row) != nil {
				return d.ErrUnavailable
			}
			op, e := r.auth.ReadOwnerExitTx(tx, row.AuthID, row.OperationID)
			if e != nil {
				return e
			}
			if op.Decision == d.Pending {
				ok, e := r.auth.ownerExitCurrentTx(tx, op, now)
				if e != nil {
					return e
				}
				if !ok {
					op, e = r.auth.DecideOwnerExitTx(tx, op.AuthID, op.OperationID, d.Cancelled, "CONDITIONS_CHANGED_OR_EXPIRED", now)
					if e != nil {
						return e
					}
				}
			}
			out = append(out, op)
		}
		return cur.Err()
	})
	return out, err
}
func (r *OwnerExitRepository) Acknowledge(ctx context.Context, expected d.Operation, status d.Status, now time.Time) error {
	return r.transaction(ctx, func(tx context.Context) error {
		op, e := r.auth.ReadOwnerExitTx(tx, expected.AuthID, expected.OperationID)
		if e != nil {
			return e
		}
		if status.AuthID != op.AuthID || status.OperationID != op.OperationID || status.Purpose != op.Purpose || status.Decision != op.Decision || op.Decision == d.Pending || op.ReceiptID != "" && status.ReceiptID != op.ReceiptID || status.ReceiptID != "" && !d.ValidReceiptID(status.ReceiptID) {
			return d.ErrConflict
		}
		if (op.Purpose == d.Withdrawal || op.Decision == d.Cancelled) && status.CleanupState != "NOT_REQUIRED" || op.Purpose == d.Closure && op.Decision == d.Committed && status.CleanupState == "NOT_REQUIRED" {
			return d.ErrUnavailable
		}
		complete := status.CleanupState == "COMPLETE" || status.CleanupState == "NOT_REQUIRED"
		if status.CleanupState != "PENDING" && !complete {
			return d.ErrUnavailable
		}
		_, e = r.auth.database.Collection(OwnerExitCollection).UpdateOne(tx, bson.M{"operationId": op.OperationID, "decision": op.Decision}, bson.M{"$set": bson.M{"notificationPending": false, "appAcknowledged": complete, "appCleanupState": status.CleanupState, "nextAttemptAt": now.Add(time.Second)}})
		return e
	})
}
func (r *OwnerExitRepository) Retry(ctx context.Context, expected d.Operation, now time.Time) error {
	return r.transaction(ctx, func(tx context.Context) error {
		op, e := r.auth.ReadOwnerExitTx(tx, expected.AuthID, expected.OperationID)
		if e != nil {
			return e
		}
		if op.Decision != expected.Decision {
			return nil
		}
		attempts := op.Attempts
		if attempts < math.MaxInt64 {
			attempts++
		}
		delay := time.Second << min(attempts-1, 6)
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
		delay = min(60*time.Second, delay+time.Duration(rand.Int64N(int64(delay/5)+1)))
		_, e = r.auth.database.Collection(OwnerExitCollection).UpdateOne(tx, bson.M{"operationId": op.OperationID, "decision": op.Decision}, bson.M{"$set": bson.M{"attempts": attempts, "nextAttemptAt": now.Add(delay)}})
		return e
	})
}
