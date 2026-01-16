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

// NewUserService constructs a UserService with required usecases and JWT util.
func NewUserService(userUsecase *biz.UserUsecase, authUsecase *biz.AuthUsecase, auditUsecase *biz.AuditUsecase, jwtUtil *util.JwtUtil, c *conf.Jwt) (*UserService, error) {
	return &UserService{userUsecase: userUsecase, authUsecase: authUsecase, auditUsecase: auditUsecase, jwtUtil: jwtUtil,
		refreshTokenLifeSpan: time.Duration(c.GetRefreshTokenLifeSpan()) * time.Second,
	}, nil
}

// UpdatePassword updates the calling user's password after verifying the old password.
// - Retrieves authenticated user id from JWT,
// - Delegates verification and update to user usecase repo,
// - Bumps cached user version via auth usecase to invalidate previous refresh tokens,
// - Returns RPC-level success or propagated errors.
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
	if err = s.authUsecase.Repo.AddOrUpdateUserVersion(ctx, claim.Uid, util.NextJWTVersion(claim.Version), s.refreshTokenLifeSpan); err != nil {
		return nil, errorProcess(ctx, err)
	}

	return successProcess(ctx, func(reqId string) *user.UpdatePasswordReply {
		return &user.UpdatePasswordReply{
			Code:    200,
			Message: "Updated successfully",
			TraceId: reqId,
		}
	}), nil
}

// DeleteAccount marks the authenticated user's account as deleted (soft delete) and bumps version.
// - Extracts user id from JWT, calls user usecase repo to perform deletion,
// - Updates cached user version to invalidate tokens,
// - Returns RPC-level result and audit info.
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
			Message: "Deleted successfully",
			TraceId: reqId,
		}
	}), nil
}

// GetProfile returns the authenticated user's profile information.
// - Extracts user id from JWT and fetches profile from user usecase repo,
// - Translates domain profile to RPC reply structure and returns it.
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
			Message: "Queried successfully",
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

// UpdateProfile updates the authenticated user's official attributes.
// - Converts incoming structpb to a string map and delegates to user usecase repo,
// - Returns RPC-level success or propagated errors.
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
			Message: "Updated successfully",
			TraceId: reqId,
		}
	}), nil
}

// GetProfileKeys returns the set of profile keys visible to the authenticated user.
// - Delegates to user usecase repo to list base and extra keys (official__*),
// - Returns them in the RPC response.
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
			Message: "Queried successfully",
			Data: &user.GetProfileKeysReply_GetProfileKeysReplyData{
				BaseKeys:         result.BaseKeys,
				ExtraProfileKeys: result.ExtraProfileKeys,
			},
			TraceId: reqId,
		}
	}), nil
}

// UpdateUserConsent records the user's consent choices for a client application.
// - Validates the caller via JWT, then delegates validation and persistence to user usecase repo.
func (s *UserService) UpdateUserConsent(ctx context.Context, in *user.UpdateUserConsentRequest) (*user.UpdateUserConsentReply, error) {
	successProcess, errorProcess := util.GetProcesses[*user.UpdateUserConsentReply]("UpdateUserConsent", GetAuditInsertFunc(*s.auditUsecase))

	claim, err := s.jwtUtil.GetBaseAuthClaims(ctx)
	if err != nil {
		return nil, errorProcess(ctx, err)
	}

	if err = s.userUsecase.Repo.UpdateUserConsent(ctx, claim.Uid, in.GetClientId(), in.GetClientVersion(), in.GetOptionalScopes()); err != nil {
		return nil, errorProcess(ctx, err)
	}
	return successProcess(ctx, func(reqId string) *user.UpdateUserConsentReply {
		return &user.UpdateUserConsentReply{
			Code:    200,
			Message: "Updated successfully",
			TraceId: reqId,
		}
	}), nil
}
