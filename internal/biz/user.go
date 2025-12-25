package biz

import "context"

type UserRepo interface {
	UpdateUserPassword(ctx context.Context, userId string, oldPassword string, newPassword string) error
}

type UserUsecase struct {
	Repo UserRepo
}

func NewUserUsecase(repo UserRepo) *UserUsecase {
	return &UserUsecase{Repo: repo}
}
