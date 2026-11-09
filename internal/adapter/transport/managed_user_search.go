package transport

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"unicode/utf8"

	statuspb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_status"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/managed_user_search"
	"github.com/go-kratos/kratos/v2/middleware"
	kt "github.com/go-kratos/kratos/v2/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	account "iwut-auth-center/internal/account/domain"
	d "iwut-auth-center/internal/managedusersearch/domain"
	"iwut-auth-center/internal/managedusersearch/usecase"
)

func managedUserSearchMethod(operation string) bool {
	return operation == pb.ManagedUserSearchService_SearchUsers_FullMethodName
}
func managedUserSearchHTTPPath(path string) bool { return path == "/v1/managed-users:search" }

type ManagedUserSearchService struct {
	pb.UnimplementedManagedUserSearchServiceServer
	service *usecase.Service
}

func NewManagedUserSearchService(service *usecase.Service) *ManagedUserSearchService {
	return &ManagedUserSearchService{service: service}
}
func (s *ManagedUserSearchService) SearchUsers(ctx context.Context, req *pb.SearchUsersRequest) (*pb.SearchUsersResponse, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	query := d.Query{}
	if req != nil && len(req.ProtoReflect().GetUnknown()) == 0 {
		switch selector := req.Selector.(type) {
		case *pb.SearchUsersRequest_AuthId:
			query = d.Query{Kind: "authId", Value: selector.AuthId}
		case *pb.SearchUsersRequest_Email:
			query = d.Query{Kind: "email", Value: selector.Email}
		}
	}
	result, err := s.service.Search(ctx, actor, query)
	if err != nil {
		return nil, managedUserSearchError(err)
	}
	out := &pb.SearchUsersResponse{Items: []*pb.ManagedUserSummary{}, AsOf: timestamppb.New(result.AsOf)}
	for _, item := range result.Items {
		state := statuspb.AccountStatus_ACCOUNT_STATUS_ACTIVE
		if item.AccountStatus == "DISABLED" {
			state = statuspb.AccountStatus_ACCOUNT_STATUS_DISABLED
		}
		summary := &pb.ManagedUserSummary{AuthId: item.AuthID, AccountStatus: state}
		if item.DeveloperStatus != "" {
			summary.DeveloperStatus = wrapperspb.String(item.DeveloperStatus)
		}
		out.Items = append(out.Items, summary)
	}
	return out, nil
}
func managedUserSearchError(err error) error {
	code, reason := codes.Unavailable, d.ErrUnavailable.Error()
	for _, item := range []struct {
		err  error
		code codes.Code
	}{
		{d.ErrIdentity, codes.Unauthenticated}, {d.ErrForbidden, codes.PermissionDenied}, {d.ErrInvalid, codes.InvalidArgument},
		{d.ErrLarge, codes.ResourceExhausted}, {d.ErrRate, codes.ResourceExhausted},
	} {
		if errors.Is(err, item.err) {
			code, reason = item.code, item.err.Error()
			break
		}
	}
	if errors.Is(err, context.Canceled) {
		code = codes.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	return transportStatus(code, reason, "managed user search failed")
}
func managedUserSearchIdentity(v *UserIdentityVerifier) middleware.Middleware {
	return func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req any) (any, error) {
			tr, ok := kt.FromServerContext(ctx)
			if !ok || !managedUserSearchMethod(tr.Operation()) {
				return nil, managedUserSearchError(d.ErrIdentity)
			}
			tr.ReplyHeader().Set("Cache-Control", "private, no-store")
			values := tr.RequestHeader().Values(UserIdentityHeader)
			if len(values) == 0 {
				return nil, transportStatus(codes.Unauthenticated, "USER_IDENTITY_REQUIRED", "user identity required")
			}
			if len(values) != 1 {
				return nil, managedUserSearchError(d.ErrIdentity)
			}
			identity, err := v.verifyIdentity(values[0])
			if err != nil {
				return nil, managedUserSearchError(d.ErrIdentity)
			}
			if !slices.Contains(identity.Permissions, "auth.account.manage") {
				return nil, managedUserSearchError(d.ErrForbidden)
			}
			message, ok := req.(proto.Message)
			if !ok || proto.Size(message) > 16*1024 {
				return nil, managedUserSearchError(d.ErrLarge)
			}
			return next(context.WithValue(account.WithIdentity(ctx, identity.AuthID, identity.AccountRevision), userIdentityContextKey{}, identity.AuthID), req)
		}
	}
}
func managedUserSearchWire(data []byte, value any) bool {
	if _, ok := value.(*pb.SearchUsersRequest); !ok {
		return true
	}
	if len(data) > 16*1024 {
		return false
	}
	// The oneof has exactly one bytes field. Multiple tags include repeated
	// branches, which standard protobuf would otherwise silently replace.
	field, typ, n := protowire.ConsumeTag(data)
	if n < 0 || (field != 1 && field != 2) || typ != protowire.BytesType {
		return false
	}
	valueBytes, size := protowire.ConsumeBytes(data[n:])
	return size >= 0 && utf8.Valid(valueBytes) && n+size == len(data)
}

// ProtoJSON ignores null oneof values; reject an extra selector even when null.
func managedUserSearchJSON(data []byte, request any) bool {
	if _, ok := request.(*pb.SearchUsersRequest); !ok {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 1 {
		return false
	}
	for key, raw := range fields {
		if key != "authId" && key != "auth_id" && key != "email" {
			return false
		}
		var value *string
		return json.Unmarshal(raw, &value) == nil && value != nil
	}
	return false
}
