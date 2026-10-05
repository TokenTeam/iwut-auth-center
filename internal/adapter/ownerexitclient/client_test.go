package ownerexitclient

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/app_center/v1/account_owner_exit"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	d "iwut-auth-center/internal/ownerexit/domain"
	"testing"
	"time"
)

func TestStatusIdentityAndCleanupValidation(t *testing.T) {
	id, _ := uuid.NewV7()
	now := time.Now()
	o := d.Operation{AuthID: "student", OperationID: uuid.NewString(), Purpose: d.Withdrawal, Decision: d.Committed, ReceiptID: id.String(), AccountRevision: 1, DeveloperRevision: 1, PermissionRevision: 1, CreatedAt: now, ExpiresAt: now.Add(time.Minute), DecidedAt: &now}
	valid := &pb.AccountOwnerExitStatus{AuthId: o.AuthID, OperationId: o.OperationID, Purpose: pb.Purpose_PURPOSE_DEVELOPER_WITHDRAWAL, Decision: pb.Decision_DECISION_COMMITTED, ReceiptId: o.ReceiptID, CleanupState: pb.CleanupState_CLEANUP_STATE_NOT_REQUIRED}
	if _, e := validate(o, valid); e != nil {
		t.Fatal(e)
	}
	for _, alter := range []func(*pb.AccountOwnerExitStatus){func(s *pb.AccountOwnerExitStatus) { s.AuthId = "other" }, func(s *pb.AccountOwnerExitStatus) { s.OperationId = uuid.NewString() }, func(s *pb.AccountOwnerExitStatus) { s.ReceiptId = "" }, func(s *pb.AccountOwnerExitStatus) { s.Decision = pb.Decision_DECISION_CANCELLED }, func(s *pb.AccountOwnerExitStatus) { s.Purpose = pb.Purpose_PURPOSE_ACCOUNT_CLOSURE }, func(s *pb.AccountOwnerExitStatus) { s.CleanupState = pb.CleanupState_CLEANUP_STATE_COMPLETE }} {
		v := proto.Clone(valid).(*pb.AccountOwnerExitStatus)
		alter(v)
		if _, e := validate(o, v); e == nil {
			t.Fatal("accepted mismatched App result", v)
		}
	}
	o.Decision = d.Cancelled
	o.ReceiptID = ""
	valid.Decision = pb.Decision_DECISION_CANCELLED
	valid.ReceiptId = ""
	if _, e := validate(o, valid); e != nil {
		t.Fatal("lost Prepare receipt cancellation rejected", e)
	}
	o.Purpose = d.Closure
	o.Decision = d.Committed
	o.ReceiptID = id.String()
	valid.Purpose = pb.Purpose_PURPOSE_ACCOUNT_CLOSURE
	valid.Decision = pb.Decision_DECISION_COMMITTED
	valid.ReceiptId = id.String()
	if _, e := validate(o, valid); e == nil {
		t.Fatal("closure accepted NOT_REQUIRED")
	}
	valid.CleanupState = pb.CleanupState_CLEANUP_STATE_PENDING
	if _, e := validate(o, valid); e != nil {
		t.Fatal(e)
	}
}

func TestRecoveryObservationKeepsTupleAndStateStrict(t *testing.T) {
	receipt, _ := uuid.NewV7()
	o := d.Operation{AuthID: "closed-user", OperationID: uuid.NewString(), Purpose: d.Closure}
	r := &pb.AccountOwnerExitStatus{AuthId: o.AuthID, OperationId: o.OperationID, Purpose: pb.Purpose_PURPOSE_ACCOUNT_CLOSURE, Decision: pb.Decision_DECISION_PENDING, ReceiptId: receipt.String(), CleanupState: pb.CleanupState_CLEANUP_STATE_NOT_REQUIRED}
	got, e := validateObserved(o, r)
	if e != nil || got.Decision != d.Pending || got.ReceiptID != r.ReceiptId {
		t.Fatal(got, e)
	}
	for _, change := range []func(*pb.AccountOwnerExitStatus){func(v *pb.AccountOwnerExitStatus) { v.AuthId = "other" }, func(v *pb.AccountOwnerExitStatus) { v.OperationId = uuid.NewString() }, func(v *pb.AccountOwnerExitStatus) { v.Purpose = pb.Purpose_PURPOSE_DEVELOPER_WITHDRAWAL }, func(v *pb.AccountOwnerExitStatus) { v.ReceiptId = "" }, func(v *pb.AccountOwnerExitStatus) { v.Decision = pb.Decision(42) }, func(v *pb.AccountOwnerExitStatus) { v.CleanupState = pb.CleanupState_CLEANUP_STATE_COMPLETE }} {
		bad := proto.Clone(r).(*pb.AccountOwnerExitStatus)
		change(bad)
		if _, e = validateObserved(o, bad); e == nil {
			t.Fatal("recovery trusted malformed observation", bad)
		}
	}
	r.Decision = pb.Decision_DECISION_COMMITTED
	r.CleanupState = pb.CleanupState_CLEANUP_STATE_PENDING
	if got, e = validateObserved(o, r); e != nil || got.Decision != d.Committed {
		t.Fatal(got, e)
	}
	r.CleanupState = pb.CleanupState_CLEANUP_STATE_COMPLETE
	if _, e = validateObserved(o, r); e != nil {
		t.Fatal(e)
	}
	r.ReceiptId = ""
	if _, e = validateObserved(o, r); e == nil {
		t.Fatal("committed receipt missing")
	}
	r.Decision = pb.Decision_DECISION_CANCELLED
	r.CleanupState = pb.CleanupState_CLEANUP_STATE_NOT_REQUIRED
	if got, e = validateObserved(o, r); e != nil || got.Decision != d.Cancelled {
		t.Fatal(got, e)
	}
	o.Decision = d.Committed
	if _, e = validateObserved(o, r); e == nil {
		t.Fatal("known decision silently weakened")
	}
}
