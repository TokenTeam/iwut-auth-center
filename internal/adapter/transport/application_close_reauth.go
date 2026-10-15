package transport

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
	"unicode/utf8"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_close_reauth"
	kerrors "github.com/go-kratos/kratos/v2/errors"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	d "iwut-auth-center/internal/applicationclosereauth/domain"
)

type ApplicationCloseReauthHandler interface {
	Begin(context.Context, []byte, string) (d.Challenge, error)
	Complete(context.Context, []byte, string, string, []byte, string, string) (d.Proof, error)
}

type ApplicationCloseReauthAdmission interface {
	AllowBegin(string, time.Time) bool
	AllowLocator(string, time.Time) bool
}

type ApplicationCloseReauthService struct {
	pb.UnimplementedApplicationCloseReauthServiceServer
	handler ApplicationCloseReauthHandler
	limiter ApplicationCloseReauthAdmission
	enabled bool
}

func NewApplicationCloseReauthService(handler ApplicationCloseReauthHandler, limiter ApplicationCloseReauthAdmission, enabled bool) *ApplicationCloseReauthService {
	return &ApplicationCloseReauthService{handler: handler, limiter: limiter, enabled: enabled}
}

func applicationCloseReauthMethod(method string) bool {
	return method == pb.ApplicationCloseReauthService_BeginApplicationCloseReauth_FullMethodName || method == pb.ApplicationCloseReauthService_CompleteApplicationCloseReauth_FullMethodName
}

func (s *ApplicationCloseReauthService) authorize(ctx context.Context, message proto.Message) ([]byte, error) {
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", "no-store"))
	if s == nil || !s.enabled || s.handler == nil || s.limiter == nil {
		return nil, closeReauthError(ctx, d.ErrUnavailable)
	}
	if message == nil || !message.ProtoReflect().IsValid() || hasUnknown(message) || proto.Size(message) > 16*1024 {
		return nil, closeReauthError(ctx, d.ErrInvalid)
	}
	if !s.limiter.AllowBegin(authenticationPeer(ctx), time.Now().UTC()) {
		return nil, closeReauthError(ctx, d.ErrRate)
	}
	var values []string
	invalid := false
	forbidden := func(k string) bool {
		return equalHeader(k, "authorization") || equalHeader(k, "cookie") || equalHeader(k, "x-iwut-identity") || equalHeader(k, "x-iwut-service-identity")
	}
	if tr, ok := kt.FromServerContext(ctx); ok {
		values = tr.RequestHeader().Values("x-iwut-session")
		for _, key := range tr.RequestHeader().Keys() {
			if forbidden(key) {
				invalid = true
			}
		}
	} else {
		md, _ := metadata.FromIncomingContext(ctx)
		values = md.Get("x-iwut-session")
		for key := range md {
			if forbidden(key) {
				invalid = true
			}
		}
	}
	if invalid || len(values) != 1 || !canonicalSessionToken(values[0]) {
		return nil, closeReauthError(ctx, d.ErrInvalid)
	}
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(values[0])
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

func (s *ApplicationCloseReauthService) BeginApplicationCloseReauth(ctx context.Context, r *pb.BeginApplicationCloseReauthRequest) (*pb.BeginApplicationCloseReauthResponse, error) {
	digest, err := s.authorize(ctx, r)
	if err != nil {
		return nil, err
	}
	if !s.limiter.AllowLocator(base64.RawURLEncoding.EncodeToString(digest), time.Now().UTC()) {
		return nil, closeReauthError(ctx, d.ErrRate)
	}
	v, err := s.handler.Begin(ctx, digest, r.ApplicationId)
	if err != nil {
		return nil, closeReauthError(ctx, err)
	}
	expires := timestamppb.New(v.ExpiresAt)
	if expires.CheckValid() != nil {
		return nil, closeReauthError(ctx, d.ErrInconsistent)
	}
	return &pb.BeginApplicationCloseReauthResponse{OperationId: v.OperationID, Challenge: v.Challenge, ExpiresAt: expires}, nil
}

func (s *ApplicationCloseReauthService) CompleteApplicationCloseReauth(ctx context.Context, r *pb.CompleteApplicationCloseReauthRequest) (*pb.CompleteApplicationCloseReauthResponse, error) {
	digest, err := s.authorize(ctx, r)
	if err != nil {
		return nil, err
	}
	if !s.limiter.AllowLocator(base64.RawURLEncoding.EncodeToString(digest), time.Now().UTC()) {
		return nil, closeReauthError(ctx, d.ErrRate)
	}
	if r.CurrentPassword == "" || len(r.CurrentPassword) > 1024 || !utf8.ValidString(r.CurrentPassword) {
		return nil, closeReauthError(ctx, d.ErrInvalid)
	}
	v, err := s.handler.Complete(ctx, digest, r.OperationId, r.ApplicationId, r.SignatureDer, r.CurrentPassword, authenticationPeer(ctx))
	if err != nil {
		return nil, closeReauthError(ctx, err)
	}
	expires := timestamppb.New(v.ExpiresAt)
	if expires.CheckValid() != nil {
		return nil, closeReauthError(ctx, d.ErrInconsistent)
	}
	return &pb.CompleteApplicationCloseReauthResponse{ProofJws: v.JWS, ExpiresAt: expires}, nil
}

func closeReauthError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, d.ErrInvalid):
		return transportStatus(codes.InvalidArgument, "ERROR_REASON_INVALID_APPLICATION_CLOSE_REAUTH_REQUEST", "invalid Application close reauthentication request")
	case errors.Is(err, d.ErrFailed):
		return transportStatus(codes.Unauthenticated, "ERROR_REASON_APPLICATION_CLOSE_REAUTH_FAILED", "Application close reauthentication failed")
	case errors.Is(err, d.ErrRate):
		_ = grpc.SetHeader(ctx, metadata.Pairs("retry-after", "60"))
		return kerrors.New(429, "ERROR_REASON_APPLICATION_CLOSE_REAUTH_RATE_LIMITED", "Application close reauthentication rate limited").WithMetadata(map[string]string{"retryAfterSeconds": "60"})
	case errors.Is(err, d.ErrInconsistent):
		return transportStatus(codes.Internal, "ERROR_REASON_APPLICATION_CLOSE_REAUTH_STATE_INCONSISTENT", "Application close reauthentication state is inconsistent")
	default:
		return transportStatus(codes.Unavailable, "ERROR_REASON_APPLICATION_CLOSE_REAUTH_UNAVAILABLE", "Application close reauthentication unavailable")
	}
}
