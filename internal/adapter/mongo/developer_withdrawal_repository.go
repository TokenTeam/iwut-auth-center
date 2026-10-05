package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	a "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	dev "iwut-auth-center/internal/developer/domain"
	d "iwut-auth-center/internal/developerwithdrawal/domain"
	o "iwut-auth-center/internal/ownerexit/domain"
	"math"
	"time"
)

type DeveloperWithdrawalRepository struct{ auth *AuthenticationRepository }

func NewDeveloperWithdrawalRepository(a *AuthenticationRepository) *DeveloperWithdrawalRepository {
	return &DeveloperWithdrawalRepository{a}
}
func EnsureDeveloperWithdrawalSchema(ctx context.Context, db *m.Database) error {
	if e := EnsureOwnerExitSchema(ctx, db); e != nil {
		return e
	}
	return EnsureDeveloperManagementSchema(ctx, db)
}
func (r *DeveloperWithdrawalRepository) tx(ctx context.Context, fn func(context.Context) error) error {
	var cause error
	e := r.auth.WithAuthTransaction(ctx, func(tx context.Context) error { cause = fn(tx); return cause })
	if e == nil {
		return nil
	}
	for _, known := range []error{d.ErrInvalid, d.ErrConflict, d.ErrSession, d.ErrWithdrawn, d.ErrNotFound} {
		if errors.Is(cause, known) {
			return known
		}
	}
	if errors.Is(cause, o.ErrConflict) {
		return d.ErrConflict
	}
	if errors.Is(cause, o.ErrNotFound) {
		return d.ErrNotFound
	}
	return d.ErrUnavailable
}
func (r *DeveloperWithdrawalRepository) session(ctx context.Context, digest []byte, now time.Time, touch bool) (a.Session, error) {
	var s a.Session
	var e error
	if touch {
		s, e = r.auth.CheckSessionTx(ctx, digest, now)
	} else {
		s, e = r.auth.CheckSessionReadTx(ctx, digest, now)
	}
	if errors.Is(e, ap.ErrSessionInvalid) {
		e = d.ErrSession
	}
	return s, e
}
func (r *DeveloperWithdrawalRepository) Authenticate(ctx context.Context, digest []byte, now time.Time) (string, error) {
	var id string
	e := r.tx(ctx, func(tx context.Context) error { s, e := r.session(tx, digest, now, false); id = s.AuthID; return e })
	return id, e
}
func (r *DeveloperWithdrawalRepository) principal(ctx context.Context, id string) (status string, ar, dr, pr int64, err error) {
	var raw bson.Raw
	err = r.auth.database.Collection(PrincipalCollection).FindOne(ctx, bson.M{"authId": id}).Decode(&raw)
	if err != nil {
		return
	}
	if !identityFields(raw, map[string]bson.Type{"accountRevision": bson.TypeInt64, "developerRevision": bson.TypeInt64, "permissionRevision": bson.TypeInt64}) {
		err = d.ErrUnavailable
		return
	}
	if !validDeveloperLifecycle(raw) {
		err = d.ErrUnavailable
		return
	}
	if value := raw.Lookup("developerStatus"); value.Type == bson.TypeString {
		status = value.StringValue()
	}
	ar = raw.Lookup("accountRevision").Int64()
	dr = raw.Lookup("developerRevision").Int64()
	pr = raw.Lookup("permissionRevision").Int64()
	if ar < 1 || pr < 1 {
		err = d.ErrUnavailable
	}
	return
}
func (r *DeveloperWithdrawalRepository) handle(ctx context.Context, id, status string) error {
	var activation bson.Raw
	if e := r.auth.database.Collection(DeveloperActivationCollection).FindOne(ctx, bson.M{"authId": id}).Decode(&activation); e != nil {
		return d.ErrUnavailable
	}
	ar := &DeveloperApplicationRepository{r.auth}
	handle, e := ar.readHandleHistory(ctx, dev.ApplicationState{AuthID: id, Status: dev.DeveloperStatus(status)}, activation)
	if e != nil || handle == "" {
		return d.ErrUnavailable
	}
	return nil
}
func (r *DeveloperWithdrawalRepository) Prepare(ctx context.Context, digest []byte, requestID, operationID string, revision int64, now time.Time) (o.Operation, error) {
	var out o.Operation
	e := r.tx(ctx, func(tx context.Context) error {
		s, e := r.session(tx, digest, now, true)
		if e != nil {
			return e
		}
		// Request replay is resolved before evaluating current developer status.
		var prior struct {
			OperationID string `bson:"operationId"`
		}
		e = r.auth.database.Collection(OwnerExitRequestCollection).FindOne(tx, bson.M{"authId": s.AuthID, "requestId": requestID, "expiresAt": bson.M{"$gt": now}}).Decode(&prior)
		if e == nil {
			out, e = r.auth.ReadOwnerExitTx(tx, s.AuthID, prior.OperationID)
			if e != nil {
				return e
			}
			if out.Purpose != o.Withdrawal || out.DeveloperRevision != revision {
				return d.ErrConflict
			}
			return nil
		}
		if !errors.Is(e, m.ErrNoDocuments) {
			return e
		}
		status, ar, dr, pr, e := r.principal(tx, s.AuthID)
		if e != nil {
			return e
		}
		if status == "WITHDRAWN" {
			return d.ErrWithdrawn
		}
		if status != "APPROVED" || dr != revision {
			return d.ErrConflict
		}
		if e = r.handle(tx, s.AuthID, status); e != nil {
			return e
		}
		out, e = r.auth.CreateOwnerExitTx(tx, o.Operation{OperationID: operationID, AuthID: s.AuthID, Purpose: o.Withdrawal, Decision: o.Pending, RequestID: requestID, SessionID: s.SessionID, AccountRevision: ar, DeveloperRevision: dr, PermissionRevision: pr, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), NextAttemptAt: now})
		return e
	})
	return out, e
}
func (r *DeveloperWithdrawalRepository) result(ctx context.Context, op o.Operation) (d.Result, error) {
	status, _, revision, _, e := r.principal(ctx, op.AuthID)
	if e != nil {
		return d.Result{}, e
	}
	state := "PREPARING"
	if op.ReceiptID != "" {
		state = "READY"
	}
	if op.Decision == o.Cancelled {
		state = "CANCELLED"
		if op.Blocker != "" {
			state = "BLOCKED"
		}
	}
	if op.Decision == o.Committed {
		state = "COMPLETED"
	}
	out := d.Result{OperationID: op.OperationID, State: state, DeveloperStatus: status, DeveloperRevision: revision, ExpiresAt: op.ExpiresAt, Blocker: op.Blocker}
	if op.Decision == o.Committed {
		out.CompletedAt = op.DecidedAt
	}
	return out, nil
}
func (r *DeveloperWithdrawalRepository) own(ctx context.Context, digest []byte, id string, now time.Time, touch bool) (a.Session, o.Operation, error) {
	s, e := r.session(ctx, digest, now, touch)
	if e != nil {
		return s, o.Operation{}, e
	}
	op, e := r.auth.ReadOwnerExitTx(ctx, s.AuthID, id)
	if e == nil && op.Purpose != o.Withdrawal {
		e = d.ErrNotFound
	}
	return s, op, e
}
func (r *DeveloperWithdrawalRepository) Read(ctx context.Context, digest []byte, id string, now time.Time) (d.Result, error) {
	var out d.Result
	e := r.tx(ctx, func(tx context.Context) error {
		_, op, e := r.own(tx, digest, id, now, false)
		if e != nil {
			return e
		}
		if op.Decision == o.Pending {
			current, e := r.auth.ownerExitCurrentTx(tx, op, now)
			if e != nil {
				return e
			}
			if !current {
				op, e = r.auth.DecideOwnerExitTx(tx, op.AuthID, id, o.Cancelled, "CONDITIONS_CHANGED_OR_EXPIRED", now)
				if e != nil {
					return e
				}
			}
		}
		out, e = r.result(tx, op)
		return e
	})
	return out, e
}
func (r *DeveloperWithdrawalRepository) Confirm(ctx context.Context, digest []byte, id string, now time.Time) (d.Result, error) {
	var out d.Result
	var stale bool
	e := r.tx(ctx, func(tx context.Context) error {
		stale = false
		s, op, e := r.own(tx, digest, id, now, true)
		if e != nil {
			return e
		}
		if op.Decision == o.Committed {
			out, e = r.result(tx, op)
			return e
		}
		if op.Decision != o.Pending || op.ReceiptID == "" || op.SessionID != s.SessionID {
			return d.ErrConflict
		}
		current, e := r.auth.ownerExitCurrentTx(tx, op, now)
		if e != nil {
			return e
		}
		if !current {
			_, e = r.auth.DecideOwnerExitTx(tx, op.AuthID, id, o.Cancelled, "CONDITIONS_CHANGED_OR_EXPIRED", now)
			stale = true
			return e
		}
		if op.DeveloperRevision == math.MaxInt64 {
			return d.ErrConflict
		}
		if e = r.handle(tx, op.AuthID, "APPROVED"); e != nil {
			return e
		}
		res, e := r.auth.database.Collection(PrincipalCollection).UpdateOne(tx, bson.M{"authId": op.AuthID, "accountStatus": "ACTIVE", "developerStatus": "APPROVED", "accountRevision": op.AccountRevision, "developerRevision": op.DeveloperRevision, "permissionRevision": op.PermissionRevision}, bson.M{"$set": bson.M{"developerStatus": "WITHDRAWN", "developerRevision": op.DeveloperRevision + 1, "developerStatusChangedAt": now}})
		if e != nil {
			return e
		}
		if res.MatchedCount != 1 {
			return d.ErrConflict
		}
		_, e = r.auth.database.Collection(DeveloperLifecycleAuditCollection).InsertOne(tx, bson.M{"eventId": uuid.NewString(), "actorAuthId": op.AuthID, "subjectAuthId": op.AuthID, "action": "WITHDRAW", "beforeStatus": "APPROVED", "afterStatus": "WITHDRAWN", "beforeRevision": op.DeveloperRevision, "afterRevision": op.DeveloperRevision + 1, "occurredAt": now, "operationId": op.OperationID})
		if e != nil {
			return e
		}
		op, e = r.auth.DecideOwnerExitTx(tx, op.AuthID, id, o.Committed, "", now)
		if e != nil {
			return e
		}
		out, e = r.result(tx, op)
		return e
	})
	if e == nil && stale {
		e = d.ErrConflict
	}
	return out, e
}
func (r *DeveloperWithdrawalRepository) Cancel(ctx context.Context, digest []byte, id string, now time.Time) (d.Result, error) {
	var out d.Result
	e := r.tx(ctx, func(tx context.Context) error {
		_, op, e := r.own(tx, digest, id, now, true)
		if e != nil {
			return e
		}
		op, e = r.auth.DecideOwnerExitTx(tx, op.AuthID, id, o.Cancelled, "USER_CANCELLED", now)
		if e != nil {
			return e
		}
		out, e = r.result(tx, op)
		return e
	})
	return out, e
}
