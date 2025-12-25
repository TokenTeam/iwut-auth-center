package user

import (
	"context"
	"iwut-auth-center/api/auth_center/v1/user"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
)

type Service struct {
	user.UnimplementedUserServer
	userUsecase *biz.UserUsecase
	jwtUtil     *util.JwtUtil
}

func (s *Service) UpdatePassword(ctx context.Context, in *user.UpdatePasswordRequest) (*user.UpdatePasswordReply, error) {
	return &user.UpdatePasswordReply{}, nil
}

func NewUserService(uc *biz.UserUsecase, jwtUtil *util.JwtUtil, c *conf.Jwt) (*Service, error) {
	return &Service{userUsecase: uc, jwtUtil: jwtUtil}, nil
}
