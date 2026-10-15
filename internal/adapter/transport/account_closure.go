package transport

import (
	"context"
	"encoding/hex"
	"errors"
	"time"
	"unicode/utf8"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_closure"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/accountclosure/domain"
	"iwut-auth-center/internal/adapter/deviceprotocol"
)

const ClosureConfirmationHeader = "x-iwut-closure-confirmation"
const ClosureReceiptHeader = "x-iwut-closure-receipt"
const closureMessageLimit = 16 * 1024

type AccountClosureHandler interface {
	Begin(context.Context, d.BeginInput) (d.Challenge, error)
	Prepare(context.Context, string, []byte, string, string) (d.Preparation, error)
	Confirm(context.Context, string, string, string, string) (d.Status, error)
	Cancel(context.Context, string, string) (d.Status, error)
	Get(context.Context, string, string) (d.Status, error)
}

type AccountClosureService struct {
	pb.UnimplementedAccountClosureServiceServer
	handler AccountClosureHandler
	enabled bool
	limiter *deviceprotocol.Limiter
}

func NewAccountClosureService(handler AccountClosureHandler, enabled bool, limiter *deviceprotocol.Limiter) *AccountClosureService {
	return &AccountClosureService{handler: handler, enabled: enabled, limiter: limiter}
}
func accountClosureMethod(method string) bool {
	switch method {
	case pb.AccountClosureService_BeginAccountClosure_FullMethodName, pb.AccountClosureService_PrepareAccountClosure_FullMethodName,
		pb.AccountClosureService_ConfirmAccountClosure_FullMethodName, pb.AccountClosureService_CancelAccountClosure_FullMethodName,
		pb.AccountClosureService_GetAccountClosure_FullMethodName:
		return true
	}
	return false
}
func closureHeader(ctx context.Context, name string) ([]string, bool) {
	if tr, ok := kt.FromServerContext(ctx); ok {
		for _, key := range tr.RequestHeader().Keys() {
			if equalHeader(key, name) {
				return tr.RequestHeader().Values(key), true
			}
		}
		return nil, false
	}
	md, _ := metadata.FromIncomingContext(ctx)
	v, ok := md[name]
	return v, ok
}
func (s *AccountClosureService) authorize(ctx context.Context, message proto.Message, tokenHeader string, mutation bool) (string, error) {
	if s == nil || s.handler == nil || s.limiter == nil || mutation && !s.enabled {
		return "", closureError(d.ErrUnavailable)
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", "no-store"))
	if !s.limiter.AllowBegin(authenticationPeer(ctx), time.Now().UTC()) {
		return "", closureError(d.ErrRate)
	}
	if message == nil || !message.ProtoReflect().IsValid() || proto.Size(message) > closureMessageLimit || len(message.ProtoReflect().GetUnknown()) > 0 {
		return "", closureError(d.ErrInvalid)
	}
	for _, name := range []string{"authorization", "x-iwut-session", UserIdentityHeader, "x-iwut-service-identity", ClosureConfirmationHeader, ClosureReceiptHeader} {
		if name == tokenHeader {
			continue
		}
		if _, present := closureHeader(ctx, name); present {
			return "", closureError(d.ErrToken)
		}
	}
	if tokenHeader == "" {
		return "", nil
	}
	values, present := closureHeader(ctx, tokenHeader)
	if !present || len(values) != 1 || !canonicalSessionToken(values[0]) {
		return "", closureError(d.ErrToken)
	}
	return values[0], nil
}
func (s *AccountClosureService) BeginAccountClosure(ctx context.Context, r *pb.BeginAccountClosureRequest) (*pb.AccountClosureChallenge, error) {
	if _, err := s.authorize(ctx, r, "", true); err != nil {
		return nil, err
	}
	in := d.BeginInput{RequestID: r.RequestId}
	locator := ""
	switch v := r.CredentialLocator.(type) {
	case *pb.BeginAccountClosureRequest_CredentialId:
		if !deviceprotocol.ValidID(v.CredentialId) {
			return nil, closureError(d.ErrInvalid)
		}
		in.CredentialID = v.CredentialId
		locator = "id:" + v.CredentialId
	case *pb.BeginAccountClosureRequest_PublicKeyFingerprint:
		if len(v.PublicKeyFingerprint) != 32 {
			return nil, closureError(d.ErrInvalid)
		}
		in.PublicKeyFingerprint = v.PublicKeyFingerprint
		locator = "key:" + hex.EncodeToString(v.PublicKeyFingerprint)
	default:
		return nil, closureError(d.ErrInvalid)
	}
	if !s.limiter.AllowLocator(locator, time.Now().UTC()) {
		return nil, closureError(d.ErrRate)
	}
	out, err := s.handler.Begin(ctx, in)
	if err != nil {
		return nil, closureError(err)
	}
	return &pb.AccountClosureChallenge{OperationId: out.OperationID, Challenge: out.Challenge, SigningPayload: out.SigningPayload,
		ExpiresAt: timestamppb.New(out.ExpiresAt), ServiceId: out.ServiceID, ApplicationId: out.ApplicationID, PolicyVersion: out.PolicyVersion}, nil
}
func (s *AccountClosureService) PrepareAccountClosure(ctx context.Context, r *pb.PrepareAccountClosureRequest) (*pb.AccountClosurePreparation, error) {
	if _, err := s.authorize(ctx, r, "", true); err != nil {
		return nil, err
	}
	if r.CurrentPassword == "" || len(r.CurrentPassword) > 1024 || !utf8.ValidString(r.CurrentPassword) {
		return nil, closureError(d.ErrInvalid)
	}
	out, err := s.handler.Prepare(ctx, r.OperationId, r.Signature, r.CurrentPassword, authenticationPeer(ctx))
	if err != nil {
		return nil, closureError(err)
	}
	response := &pb.AccountClosurePreparation{OperationId: out.OperationID, ConfirmationToken: out.ConfirmationToken, ReceiptToken: out.ReceiptToken}
	switch out.Outcome {
	case "READY":
		response.Outcome = pb.PreparationOutcome_PREPARATION_OUTCOME_READY
	case "PREPARING":
		response.Outcome = pb.PreparationOutcome_PREPARATION_OUTCOME_PREPARING
	case "BLOCKED":
		response.Outcome = pb.PreparationOutcome_PREPARATION_OUTCOME_BLOCKED
	default:
		return nil, closureError(d.ErrUnavailable)
	}
	blockers := map[string]pb.Blocker{"": pb.Blocker_BLOCKER_NONE, "ADMIN_HANDOVER_REQUIRED": pb.Blocker_BLOCKER_ADMIN_HANDOVER_REQUIRED,
		"DEVELOPER_WITHDRAWAL_REQUIRED": pb.Blocker_BLOCKER_DEVELOPER_WITHDRAWAL_REQUIRED, "OWNED_APPLICATIONS": pb.Blocker_BLOCKER_OWNED_APPLICATIONS,
		"PENDING_OWNERSHIP_CHANGE": pb.Blocker_BLOCKER_PENDING_OWNERSHIP_CHANGE, "LIFECYCLE_OPERATION_PENDING": pb.Blocker_BLOCKER_LIFECYCLE_OPERATION_PENDING}
	b, ok := blockers[out.Blocker]
	if !ok {
		return nil, closureError(d.ErrUnavailable)
	}
	response.Blocker = b
	if p := out.Preview; p != nil {
		if p.AuditRetentionDays < 0 || p.BackupRetentionDays < 0 {
			return nil, closureError(d.ErrUnavailable)
		}
		response.Preview = &pb.AccountClosurePreview{AuthId: p.AuthID, DeveloperHandle: p.DeveloperHandle, PolicyVersion: p.PolicyVersion,
			Irreversible: p.Irreversible, DataToDelete: p.DataToDelete, PermanentRetention: p.PermanentRetention, ExpiresAt: timestamppb.New(p.ExpiresAt),
			AuditRetentionDays: uint32(p.AuditRetentionDays), BackupRetentionDays: uint32(p.BackupRetentionDays)}
	}
	return response, nil
}
func (s *AccountClosureService) ConfirmAccountClosure(ctx context.Context, r *pb.ConfirmAccountClosureRequest) (*pb.AccountClosureStatus, error) {
	token, err := s.authorize(ctx, r, ClosureConfirmationHeader, true)
	if err != nil {
		return nil, err
	}
	out, err := s.handler.Confirm(ctx, r.OperationId, token, r.Confirmation, r.PolicyVersion)
	return closureStatus(out, err)
}
func (s *AccountClosureService) CancelAccountClosure(ctx context.Context, r *pb.CancelAccountClosureRequest) (*pb.AccountClosureStatus, error) {
	token, err := s.authorize(ctx, r, ClosureConfirmationHeader, false)
	if err != nil {
		return nil, err
	}
	out, err := s.handler.Cancel(ctx, r.OperationId, token)
	return closureStatus(out, err)
}
func (s *AccountClosureService) GetAccountClosure(ctx context.Context, r *pb.GetAccountClosureRequest) (*pb.AccountClosureStatus, error) {
	token, err := s.authorize(ctx, r, ClosureReceiptHeader, false)
	if err != nil {
		return nil, err
	}
	out, err := s.handler.Get(ctx, r.OperationId, token)
	return closureStatus(out, err)
}
func closureStatus(out d.Status, err error) (*pb.AccountClosureStatus, error) {
	if err != nil {
		return nil, closureError(err)
	}
	states := map[string]pb.ClosureState{d.Preparing: pb.ClosureState_CLOSURE_STATE_PREPARING, d.Ready: pb.ClosureState_CLOSURE_STATE_READY,
		d.Cancelled: pb.ClosureState_CLOSURE_STATE_CANCELLED, d.TerminationPending: pb.ClosureState_CLOSURE_STATE_TERMINATION_PENDING,
		d.Terminated: pb.ClosureState_CLOSURE_STATE_TERMINATED, d.CleanupComplete: pb.ClosureState_CLOSURE_STATE_CLEANUP_COMPLETE}
	state, ok := states[out.State]
	if !ok {
		return nil, closureError(d.ErrUnavailable)
	}
	progress := map[string]pb.CleanupProgress{"NOT_STARTED": pb.CleanupProgress_CLEANUP_PROGRESS_NOT_STARTED, "AUTH_PENDING": pb.CleanupProgress_CLEANUP_PROGRESS_AUTH_PENDING,
		"APP_PENDING": pb.CleanupProgress_CLEANUP_PROGRESS_APP_PENDING, "COMPLETE": pb.CleanupProgress_CLEANUP_PROGRESS_COMPLETE}
	step, ok := progress[out.CleanupProgress]
	if !ok {
		return nil, closureError(d.ErrUnavailable)
	}
	r := &pb.AccountClosureStatus{State: state, CleanupProgress: step}
	if out.TerminatedAt != nil {
		r.TerminatedAt = timestamppb.New(*out.TerminatedAt)
	}
	if out.BackupExpiryUpperBound != nil {
		r.BackupExpiryUpperBound = timestamppb.New(*out.BackupExpiryUpperBound)
	}
	return r, nil
}
func closureError(err error) error {
	code := codes.Unavailable
	reason := d.ErrUnavailable
	switch {
	case errors.Is(err, d.ErrInvalid):
		code = codes.InvalidArgument
		reason = d.ErrInvalid
	case errors.Is(err, d.ErrProof):
		code = codes.Unauthenticated
		reason = d.ErrProof
	case errors.Is(err, d.ErrToken):
		code = codes.Unauthenticated
		reason = d.ErrToken
	case errors.Is(err, d.ErrConflict):
		code = codes.Aborted
		reason = d.ErrConflict
	case errors.Is(err, d.ErrRate):
		code = codes.ResourceExhausted
		reason = d.ErrRate
	}
	return transportStatus(code, reason.Error(), reason.Error())
}
