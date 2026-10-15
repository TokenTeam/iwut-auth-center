package transport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/credential_management"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	"time"
)

type CredentialManagementHandler interface {
	List(context.Context, []byte, int, string) (d.Page, error)
	SetLabel(context.Context, []byte, string, string, int64) (d.LabelResult, error)
	Begin(context.Context, []byte, string, string) (d.Started, error)
	Complete(context.Context, []byte, string, []byte, string, string) error
}
type CredentialManagementAdmission interface{ AllowSource(string, time.Time) bool }
type CredentialManagementService struct {
	pb.UnimplementedCredentialManagementServiceServer
	handler   CredentialManagementHandler
	admission CredentialManagementAdmission
}

func NewCredentialManagementService(h CredentialManagementHandler, a CredentialManagementAdmission) *CredentialManagementService {
	return &CredentialManagementService{handler: h, admission: a}
}
func credentialManagementMethod(method string) bool {
	switch method {
	case pb.CredentialManagementService_ListOwnCredentials_FullMethodName, pb.CredentialManagementService_SetOwnCredentialLabel_FullMethodName, pb.CredentialManagementService_BeginOtherCredentialRevocation_FullMethodName, pb.CredentialManagementService_CompleteOtherCredentialRevocation_FullMethodName:
		return true
	}
	return false
}
func credentialManagementHTTPPath(path string) bool {
	switch path {
	case "/v1/users/me/credentials:list", "/v1/users/me/credentials:set-label", "/v1/users/me/credentials/revocation:begin", "/v1/users/me/credentials/revocation:complete":
		return true
	}
	return false
}
func (s *CredentialManagementService) authorize(ctx context.Context, r proto.Message) ([]byte, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", "no-store"))
	if s == nil || s.handler == nil || s.admission == nil {
		return nil, transportStatus(codes.Unimplemented, "CREDENTIAL_MANAGEMENT_DISABLED", "credential management is disabled")
	}
	if !s.admission.AllowSource(authenticationPeer(ctx), time.Now().UTC()) {
		return nil, credentialManagementError(ctx, d.ErrRate)
	}
	if r == nil || !r.ProtoReflect().IsValid() {
		return nil, credentialManagementError(ctx, d.ErrInvalid)
	}
	if proto.Size(r) > 16384 {
		return nil, credentialManagementTooLarge()
	}
	if hasUnknown(r) {
		return nil, credentialManagementError(ctx, d.ErrInvalid)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("x-iwut-session")
	invalid := false
	forbidden := func(k string) bool {
		return equalHeader(k, "authorization") || equalHeader(k, "cookie") || equalHeader(k, "x-iwut-identity") || equalHeader(k, "x-iwut-service-identity")
	}
	for key := range md {
		if forbidden(key) {
			invalid = true
		}
	}
	if tr, ok := kt.FromServerContext(ctx); ok {
		values = tr.RequestHeader().Values("x-iwut-session")
		for _, key := range tr.RequestHeader().Keys() {
			if forbidden(key) {
				invalid = true
			}
		}
	}
	if invalid || len(values) != 1 || !canonicalSessionToken(values[0]) {
		return nil, credentialManagementError(ctx, d.ErrSession)
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(values[0])
	digest := sha256.Sum256(raw)
	return digest[:], nil
}
func (s *CredentialManagementService) ListOwnCredentials(ctx context.Context, r *pb.ListOwnCredentialsRequest) (*pb.OwnCredentialPage, error) {
	digest, err := s.authorize(ctx, r)
	if err != nil {
		return nil, err
	}
	size := 10
	if r.PageSize != nil {
		size = int(*r.PageSize)
	}
	page, err := s.handler.List(ctx, digest, size, r.Cursor)
	if err != nil {
		return nil, credentialManagementError(ctx, err)
	}
	out := &pb.OwnCredentialPage{CurrentCredentialId: page.CurrentCredentialID, ObservedAt: timestamppb.New(page.ObservedAt), NextCursor: page.NextCursor, Credentials: []*pb.OwnCredentialSummary{}}
	if out.ObservedAt.CheckValid() != nil {
		return nil, credentialManagementError(ctx, d.ErrUnavailable)
	}
	for _, row := range page.Credentials {
		stamp := timestamppb.New(row.CreatedAt)
		if stamp.CheckValid() != nil {
			return nil, credentialManagementError(ctx, d.ErrUnavailable)
		}
		out.Credentials = append(out.Credentials, &pb.OwnCredentialSummary{CredentialId: row.CredentialID, Label: row.Label, LabelRevision: row.LabelRevision, CreatedAt: stamp, IsCurrent: row.IsCurrent})
	}
	return out, nil
}
func (s *CredentialManagementService) SetOwnCredentialLabel(ctx context.Context, r *pb.SetOwnCredentialLabelRequest) (*pb.OwnCredentialLabel, error) {
	digest, err := s.authorize(ctx, r)
	if err != nil {
		return nil, err
	}
	if r.Label == nil || r.ExpectedLabelRevision == nil {
		return nil, credentialManagementError(ctx, d.ErrInvalid)
	}
	out, err := s.handler.SetLabel(ctx, digest, r.CredentialId, *r.Label, *r.ExpectedLabelRevision)
	if err != nil {
		return nil, credentialManagementError(ctx, err)
	}
	return &pb.OwnCredentialLabel{CredentialId: out.CredentialID, Label: out.Label, LabelRevision: out.Revision}, nil
}
func (s *CredentialManagementService) BeginOtherCredentialRevocation(ctx context.Context, r *pb.BeginOtherCredentialRevocationRequest) (*pb.CredentialRevocationStarted, error) {
	digest, err := s.authorize(ctx, r)
	if err != nil {
		return nil, err
	}
	out, err := s.handler.Begin(ctx, digest, r.RequestId, r.TargetCredentialId)
	if err != nil {
		return nil, credentialManagementError(ctx, err)
	}
	op := out.Operation
	stamp := timestamppb.New(op.ExpiresAt)
	if stamp.CheckValid() != nil {
		return nil, credentialManagementError(ctx, d.ErrUnavailable)
	}
	return &pb.CredentialRevocationStarted{OperationId: op.OperationID, CurrentSessionId: op.SessionID, CurrentCredentialId: op.CallerCredentialID, TargetCredentialId: op.TargetCredentialID, Challenge: op.Challenge, ExpiresAt: stamp, SigningPayload: out.SigningPayload}, nil
}
func (s *CredentialManagementService) CompleteOtherCredentialRevocation(ctx context.Context, r *pb.CompleteOtherCredentialRevocationRequest) (*authpb.CredentialRevoked, error) {
	digest, err := s.authorize(ctx, r)
	if err != nil {
		return nil, err
	}
	if err = s.handler.Complete(ctx, digest, r.OperationId, r.SignatureDer, r.CurrentPassword, authenticationPeer(ctx)); err != nil {
		return nil, credentialManagementError(ctx, err)
	}
	return &authpb.CredentialRevoked{}, nil
}
func credentialManagementTooLarge() error {
	return transportStatus(codes.ResourceExhausted, "CREDENTIAL_MANAGEMENT_REQUEST_TOO_LARGE", "credential management request is too large")
}
func credentialManagementError(ctx context.Context, err error) error {
	code := codes.Unavailable
	reason := d.ErrUnavailable
	switch {
	case errors.Is(err, d.ErrInvalid), errors.Is(err, d.ErrCursor), errors.Is(err, d.ErrCurrent):
		code = codes.InvalidArgument
		reason = err
	case errors.Is(err, d.ErrSession), errors.Is(err, d.ErrProof):
		code = codes.Unauthenticated
		reason = err
	case errors.Is(err, d.ErrNotFound):
		code = codes.NotFound
		reason = d.ErrNotFound
	case errors.Is(err, d.ErrLabelConflict):
		code = codes.Aborted
		reason = d.ErrLabelConflict
	case errors.Is(err, d.ErrConflict), errors.Is(err, d.ErrCompleted):
		code = codes.AlreadyExists
		reason = err
	case errors.Is(err, d.ErrRate):
		_ = grpc.SetHeader(ctx, metadata.Pairs("retry-after", "60"))
		return kerrors.New(429, d.ErrRate.Error(), "credential management rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "60"})
	}
	return transportStatus(code, reason.Error(), reason.Error())
}
