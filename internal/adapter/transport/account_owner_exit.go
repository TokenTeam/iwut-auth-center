package transport

import (
	"context"
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_owner_exit"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	d "iwut-auth-center/internal/ownerexit/domain"
	p "iwut-auth-center/internal/ownerexit/port"
)

const PermissionOwnerExitRead = "auth.account-owner-exit.read"

type OwnerExitDecisionService struct {
	pb.UnimplementedAccountOwnerExitDecisionServiceServer
	repository   p.Repository
	appServiceID string
}

func NewOwnerExitDecisionService(r p.Repository, appServiceID string) *OwnerExitDecisionService {
	return &OwnerExitDecisionService{repository: r, appServiceID: appServiceID}
}
func (s *OwnerExitDecisionService) GetAccountOwnerExitDecision(ctx context.Context, r *pb.GetAccountOwnerExitDecisionRequest) (*pb.GetAccountOwnerExitDecisionResponse, error) {
	identity, ok := serviceIdentityFromContext(ctx)
	if !ok || identity.ServiceID != s.appServiceID || !identity.HasPermission(PermissionOwnerExitRead) {
		return nil, transportStatus(codes.PermissionDenied, "OWNER_EXIT_READ_FORBIDDEN", "App service identity required")
	}
	if r == nil || hasUnknown(r) || proto.Size(r) > 16*1024 || !d.ValidAuthID(r.AuthId) || !d.ValidOperationID(r.OperationId) {
		return nil, transportStatus(codes.InvalidArgument, d.ErrInvalid.Error(), "invalid request")
	}
	op, e := s.repository.Get(ctx, r.AuthId, r.OperationId)
	if errors.Is(e, d.ErrNotFound) {
		return nil, transportStatus(codes.NotFound, d.ErrNotFound.Error(), "operation not found")
	}
	if e != nil {
		return nil, transportStatus(codes.Unavailable, d.ErrUnavailable.Error(), "decision unavailable")
	}
	purpose := pb.Purpose_PURPOSE_ACCOUNT_CLOSURE
	if op.Purpose == d.Withdrawal {
		purpose = pb.Purpose_PURPOSE_DEVELOPER_WITHDRAWAL
	}
	decision := pb.Decision_DECISION_PENDING
	if op.Decision == d.Committed {
		decision = pb.Decision_DECISION_COMMITTED
	} else if op.Decision == d.Cancelled {
		decision = pb.Decision_DECISION_CANCELLED
	}
	return &pb.GetAccountOwnerExitDecisionResponse{Decision: decision, Purpose: purpose, ReceiptId: op.ReceiptID}, nil
}
