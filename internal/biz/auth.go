package biz

import (
	"context"
	"time"
)

type AuthRepo interface {
	CheckPasswordWithEmailAndGetUserIdAndVersion(ctx context.Context, email, password string) (string, int, error)
	TryInsertRegisterCaptcha(ctx context.Context, email string, captcha string, ttl time.Duration) error
	CheckCaptchaUsable(ctx context.Context, email string, captcha string, ttl time.Duration) error
	RegisterUser(ctx context.Context, email string, password string) (string, error)
	AddOrUpdateUserVersion(ctx context.Context, userId string, version int, ttl time.Duration) error
	GetUserVersion(ctx context.Context, userId string, ttl time.Duration) (int, error)
}

type AuthUsecase struct {
	Repo AuthRepo
}

func NewAuthUsecase(repo AuthRepo) *AuthUsecase {
	return &AuthUsecase{Repo: repo}
}
