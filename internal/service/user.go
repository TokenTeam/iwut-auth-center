package service

import (
	"context"
	"fmt"
	"iwut-auth-center/api/auth_center/v1/user"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type UserService struct {
	user.UnimplementedUserServer
	userUsecase          *biz.UserUsecase
	authUsecase          *biz.AuthUsecase
	auditUsecase         *biz.AuditUsecase
	jwtUtil              *util.JwtUtil
	refreshTokenLifeSpan time.Duration
}

func NewUserService(userUsecase *biz.UserUsecase, authUsecase *biz.AuthUsecase, auditUsecase *biz.AuditUsecase, jwtUtil *util.JwtUtil, c *conf.Jwt) (*UserService, error) {
	return &UserService{userUsecase: userUsecase, authUsecase: authUsecase, auditUsecase: auditUsecase, jwtUtil: jwtUtil,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
	}, nil
}

func (s *UserService) UpdatePassword(ctx context.Context, in *user.UpdatePasswordRequest) (*user.UpdatePasswordReply, error) {
	successProcess, errorProcess := util.GetProcesses[*user.UpdatePasswordReply]("UpdatePassword", GetAuditInsertFunc(*s.auditUsecase))

	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	err = s.userUsecase.Repo.UpdateUserPassword(ctx, claim.Uid, in.OldPassword, in.NewPassword)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	// 即使 AddOrUpdateUserVersion 失败，也交给统一 errorProcess 处理
	if err = s.authUsecase.Repo.AddOrUpdateUserVersion(ctx, claim.Uid, util.NextJWTVersion(claim.Version), s.refreshTokenLifeSpan); err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *user.UpdatePasswordReply {
		return &user.UpdatePasswordReply{
			Code:    200,
			Message: "Success",
			TraceId: reqId,
		}
	}), nil
}

func (s *UserService) DeleteAccount(ctx context.Context, _ *emptypb.Empty) (*user.DeleteAccountReply, error) {
	successProcess, errorProcess := util.GetProcesses[*user.DeleteAccountReply]("DeleteAccount", GetAuditInsertFunc(*s.auditUsecase))

	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	if err = s.userUsecase.Repo.DeleteUserAccount(ctx, claim.Uid); err != nil {
		return nil, errorProcess(ctx, err)
	}
	if err = s.authUsecase.Repo.AddOrUpdateUserVersion(ctx, claim.Uid, util.NextJWTVersion(claim.Version), s.refreshTokenLifeSpan); err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *user.DeleteAccountReply {
		return &user.DeleteAccountReply{
			Code:    200,
			Message: "Success",
			TraceId: reqId,
		}
	}), nil
}

func (s *UserService) GetProfile(ctx context.Context, _ *emptypb.Empty) (*user.GetProfileReply, error) {
	successProcess, errorProcess := util.GetProcesses[*user.GetProfileReply]("GetProfile", GetAuditInsertFunc(*s.auditUsecase))

	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	userProfile, err := s.userUsecase.Repo.GetUserProfileById(ctx, claim.Uid)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *user.GetProfileReply {
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
			TraceId: reqId,
		}
	}), nil
}

func (s *UserService) UpdateProfile(ctx context.Context, in *structpb.Struct) (*user.UpdateProfileReply, error) {
	successProcess, errorProcess := util.GetProcesses[*user.UpdateProfileReply]("UpdateProfile", GetAuditInsertFunc(*s.auditUsecase))

	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	attrs := make(map[string]string)
	for key, value := range in.GetFields() {
		attrs[key] = value.GetStringValue()
		if attrs[key] == "" {
			fmt.Printf("attrs[%s] is empty\n", key)
		}
	}
	if err = s.userUsecase.Repo.UpdateUserProfile(ctx, claim.Uid, attrs); err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *user.UpdateProfileReply {
		return &user.UpdateProfileReply{
			Code:    200,
			Message: "Success",
			TraceId: reqId,
		}
	}), nil
}

func (s *UserService) GetProfileKeys(ctx context.Context, _ *emptypb.Empty) (*user.GetProfileKeysReply, error) {
	successProcess, errorProcess := util.GetProcesses[*user.GetProfileKeysReply]("GetProfileKeys", GetAuditInsertFunc(*s.auditUsecase))

	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}
	result, err := s.userUsecase.Repo.GetUserProfileKeysById(ctx, claim.Uid)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *user.GetProfileKeysReply {
		return &user.GetProfileKeysReply{
			Code:    200,
			Message: "Query successful",
			Data: &user.GetProfileKeysReply_GetProfileKeysReplyData{
				BaseKeys:         result.BaseKeys,
				ExtraProfileKeys: result.ExtraProfileKeys,
			},
			TraceId: reqId,
		}
	}), nil
}
