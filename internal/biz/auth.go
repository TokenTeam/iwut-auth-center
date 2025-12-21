package biz

import (
	"context"
	"iwut-auth-center/api/auth_center/v1/auth"

	"github.com/go-kratos/kratos/v2/errors"
)

var (
	// ErrUserNotFound is user not found.
	ErrUserNotFound = errors.NotFound(auth.ErrorReason_USER_NOT_FOUND.String(), "user not found")
)

type AuthRepo interface {
	GetPasswordByEmail(context context.Context, email string) (string, error)
	CheckPasswordAndGetUserBaseInfo(ctx context.Context, email, password string) (string, error)
}

type AuthUsecase struct {
	Repo AuthRepo
}

func NewAuthUsecase(repo AuthRepo) *AuthUsecase {
	return &AuthUsecase{Repo: repo}
}
