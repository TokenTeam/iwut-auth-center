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
