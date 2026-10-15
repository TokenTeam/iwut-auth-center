package transport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/session_management"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/sessionmanagement/domain"
)

const sessionManagementLimit = 16 * 1024
const invalidManagementSession = "INVALID_SESSION_TOKEN"

type SessionManagementHandler interface {
	List(context.Context, []byte, int, string) (d.Page, error)
	Revoke(context.Context, []byte, []string) error
}
type SessionManagementAdmission interface{ AllowSource(string, time.Time) bool }
type SessionManagementService struct {
	pb.UnimplementedSessionManagementServiceServer
	handler   SessionManagementHandler
	admission SessionManagementAdmission
}

func NewSessionManagementService(h SessionManagementHandler, a SessionManagementAdmission) *SessionManagementService {
	return &SessionManagementService{handler: h, admission: a}
}
func sessionManagementMethod(method string) bool {
	return method == pb.SessionManagementService_ListOwnSessions_FullMethodName || method == pb.SessionManagementService_RevokeOwnSessions_FullMethodName
}
func (s *SessionManagementService) authorize(ctx context.Context, r proto.Message) ([]byte, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", "no-store"))
	if s == nil || s.handler == nil || s.admission == nil {
		return nil, sessionManagementError(ctx, d.ErrUnavailable)
	}
	if !s.admission.AllowSource(authenticationPeer(ctx), time.Now().UTC()) {
		return nil, sessionManagementError(ctx, d.ErrRateLimited)
	}
	if r == nil || !r.ProtoReflect().IsValid() || hasUnknown(r) || proto.Size(r) > sessionManagementLimit {
		return nil, sessionManagementError(ctx, d.ErrInvalidRequest)
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
		return nil, transportStatus(codes.InvalidArgument, invalidManagementSession, "invalid Session carrier")
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(values[0])
	digest := sha256.Sum256(raw)
	return digest[:], nil
}
func (s *SessionManagementService) ListOwnSessions(ctx context.Context, r *pb.ListOwnSessionsRequest) (*pb.OwnSessionPage, error) {
	digest, e := s.authorize(ctx, r)
	if e != nil {
		return nil, e
	}
	size := 10
	if r.PageSize != nil {
		size = int(*r.PageSize)
	}
	p, e := s.handler.List(ctx, digest, size, r.Cursor)
	if e != nil {
		return nil, sessionManagementError(ctx, e)
	}
	out := &pb.OwnSessionPage{CurrentSessionId: p.CurrentSessionID, ObservedAt: timestamppb.New(p.ObservedAt), NextCursor: p.NextCursor, Sessions: []*pb.OwnSessionSummary{}}
	if out.ObservedAt.CheckValid() != nil {
		return nil, sessionManagementError(ctx, d.ErrUnavailable)
	}
	for _, v := range p.Sessions {
		var method pb.AuthenticationMethod
		switch v.AuthenticationMethod {
		case "DEVICE_CREDENTIAL":
			method = pb.AuthenticationMethod_DEVICE_CREDENTIAL
		case "EMAIL_CODE_AND_DEVICE":
			method = pb.AuthenticationMethod_EMAIL_CODE_AND_DEVICE
		case "PASSWORD_AND_DEVICE":
			method = pb.AuthenticationMethod_PASSWORD_AND_DEVICE
		case "PASSWORD_AND_SESSION":
			method = pb.AuthenticationMethod_PASSWORD_AND_SESSION
		default:
			return nil, sessionManagementError(ctx, d.ErrUnavailable)
		}
		row := &pb.OwnSessionSummary{SessionId: v.SessionID, CredentialId: v.CredentialID, AuthenticationMethod: method, AuthenticatedAt: timestamppb.New(v.AuthenticatedAt), CreatedAt: timestamppb.New(v.CreatedAt), LastUsedAt: timestamppb.New(v.LastUsedAt), ExpiresAt: timestamppb.New(v.ExpiresAt), IsCurrent: v.IsCurrent}
		for _, stamp := range []*timestamppb.Timestamp{row.AuthenticatedAt, row.CreatedAt, row.LastUsedAt, row.ExpiresAt} {
			if stamp.CheckValid() != nil {
				return nil, sessionManagementError(ctx, d.ErrUnavailable)
			}
		}
		out.Sessions = append(out.Sessions, row)
	}
	return out, nil
}
func (s *SessionManagementService) RevokeOwnSessions(ctx context.Context, r *pb.RevokeOwnSessionsRequest) (*pb.SessionsRevoked, error) {
	digest, e := s.authorize(ctx, r)
	if e != nil {
		return nil, e
	}
	if e = s.handler.Revoke(ctx, digest, r.SessionIds); e != nil {
		return nil, sessionManagementError(ctx, e)
	}
	return &pb.SessionsRevoked{}, nil
}
func sessionManagementError(ctx context.Context, e error) error {
	switch {
	case errors.Is(e, d.ErrInvalidRequest):
		return transportStatus(codes.InvalidArgument, d.ErrInvalidRequest.Error(), "invalid Session management request")
	case errors.Is(e, d.ErrInvalidCursor):
		return transportStatus(codes.InvalidArgument, d.ErrInvalidCursor.Error(), "invalid Session management request")
	case errors.Is(e, d.ErrCurrentSession):
		return transportStatus(codes.InvalidArgument, d.ErrCurrentSession.Error(), "invalid Session management request")
	case errors.Is(e, d.ErrSessionInvalid):
		return transportStatus(codes.Unauthenticated, d.ErrSessionInvalid.Error(), "Session is invalid")
	case errors.Is(e, d.ErrRateLimited):
		_ = grpc.SetHeader(ctx, metadata.Pairs("retry-after", "60"))
		return kerrors.New(429, d.ErrRateLimited.Error(), "Session management rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "60"})
	default:
		return transportStatus(codes.Unavailable, d.ErrUnavailable.Error(), "Session management unavailable")
	}
}
