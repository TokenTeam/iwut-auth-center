package user

import (
	"context"
	"fmt"
	"iwut-auth-center/api/auth_center/v1/user"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type Service struct {
	user.UnimplementedUserServer
	userUsecase          *biz.UserUsecase
	authUsecase          *biz.AuthUsecase
	jwtUtil              *util.JwtUtil
	refreshTokenLifeSpan time.Duration
}

func NewUserService(userUsecase *biz.UserUsecase, authUsecase *biz.AuthUsecase, jwtUtil *util.JwtUtil, c *conf.Jwt) (*Service, error) {
	return &Service{userUsecase: userUsecase, authUsecase: authUsecase, jwtUtil: jwtUtil,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
	}, nil
}

func (s *Service) UpdatePassword(ctx context.Context, in *user.UpdatePasswordRequest) (*user.UpdatePasswordReply, error) {
	reqId := util.RequestIDFrom(ctx)
	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	err = s.userUsecase.Repo.UpdateUserPassword(ctx, claim.Uid, in.OldPassword, in.NewPassword)
	if err != nil {
		if _, ok := interface{}(err).(interface {
			GetMetadata() map[string]string
		}); ok {
			return nil, err
		}
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	err = s.authUsecase.Repo.AddOrUpdateUserVersion(ctx, claim.Uid, util.NextJWTVersion(claim.Version), s.refreshTokenLifeSpan)
	return &user.UpdatePasswordReply{
		Code: 200,
	}, nil
}

func (s *Service) DeleteAccount(ctx context.Context, _ *emptypb.Empty) (*user.DeleteAccountReply, error) {
	reqId := util.RequestIDFrom(ctx)
	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	err = s.userUsecase.Repo.DeleteUserAccount(ctx, claim.Uid)
	if err != nil {
		if _, ok := interface{}(err).(interface {
			GetMetadata() map[string]string
		}); ok {
			return nil, err
		}
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	err = s.authUsecase.Repo.AddOrUpdateUserVersion(ctx, claim.Uid, util.NextJWTVersion(claim.Version), s.refreshTokenLifeSpan)
	return &user.DeleteAccountReply{Code: 200}, nil
}

func (s *Service) GetProfile(ctx context.Context, _ *emptypb.Empty) (*user.GetProfileReply, error) {
	reqId := util.RequestIDFrom(ctx)

	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	userProfile, err := s.userUsecase.Repo.GetUserProfileById(ctx, claim.Uid)
	if err != nil {
		if _, ok := interface{}(err).(interface {
			GetMetadata() map[string]string
		}); ok {
			return nil, err
		}
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	return &user.GetProfileReply{
		Code:    200,
		Message: "Success",
		Data: &user.GetProfileReply_GetProfileReplyData{
			UserId:    userProfile.UserId,
			Email:     userProfile.Email,
			CreatedAt: userProfile.CreatedAt,
			UpdatedAt: userProfile.UpdatedAt,
			Attrs:     userProfile.OfficialAttrs,
		},
	}, nil

}
func (s *Service) UpdateProfile(ctx context.Context, in *structpb.Struct) (*user.UpdateProfileReply, error) {
	reqId := util.RequestIDFrom(ctx)
	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	attrs := make(map[string]string)
	for key, value := range in.GetFields() {
		attrs[key] = value.GetStringValue()
		if attrs[key] == "" {
			fmt.Printf("attrs[%s] is empty\n", key)
		}
	}
	err = s.userUsecase.Repo.UpdateUserProfile(ctx, claim.Uid, attrs)
	if err != nil {
		if _, ok := interface{}(err).(interface {
			GetMetadata() map[string]string
		}); ok {
			return nil, err
		}
		err := errors.InternalServer("", err.Error())
		err.Metadata["traceId"] = reqId
		return nil, err
	}
	return &user.UpdateProfileReply{
		Code:    200,
		Message: "Success",
	}, nil
}
