package transport

import (
	"context"
	"errors"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_user_storage"
	"google.golang.org/grpc/codes"

	d "iwut-auth-center/internal/applicationuserstorage/domain"
	"iwut-auth-center/internal/applicationuserstorage/usecase"
)

func applicationUserStorageMethod(operation string) bool {
	return operation == pb.ApplicationUserStorageService_ClearOwnApplicationUserStorage_FullMethodName
}

type ApplicationUserStorageService struct {
	pb.UnimplementedApplicationUserStorageServiceServer
	service *usecase.Service
}

func NewApplicationUserStorageService(service *usecase.Service) *ApplicationUserStorageService {
	return &ApplicationUserStorageService{service: service}
}

func (s *ApplicationUserStorageService) ClearOwnApplicationUserStorage(ctx context.Context, request *pb.ClearOwnApplicationUserStorageRequest) (*pb.ClearOwnApplicationUserStorageResponse, error) {
	authID, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || len(request.ProtoReflect().GetUnknown()) != 0 {
		return nil, applicationUserStorageError(d.ErrInvalid)
	}
	changed, err := s.service.Clear(ctx, authID, request.ApplicationId)
	if err != nil {
		return nil, applicationUserStorageError(err)
	}
	return &pb.ClearOwnApplicationUserStorageResponse{Changed: changed}, nil
}

func applicationUserStorageError(err error) error {
	switch {
	case errors.Is(err, d.ErrIdentity):
		return transportStatus(codes.Unauthenticated, d.ErrIdentity.Error(), "application user storage identity is invalid")
	case errors.Is(err, d.ErrInvalid):
		return transportStatus(codes.InvalidArgument, d.ErrInvalid.Error(), "application user storage request is invalid")
	default:
		return transportStatus(codes.Unavailable, d.ErrUnavailable.Error(), "application user storage is unavailable")
	}
}
