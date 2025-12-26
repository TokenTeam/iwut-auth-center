package biz

import "context"

type UserRepo interface {
	UpdateUserPassword(ctx context.Context, userId string, oldPassword string, newPassword string) error
	DeleteUserAccount(ctx context.Context, userId string) error
	GetUserProfileById(ctx context.Context, userId string) (*UserProfile, error)
	UpdateUserProfile(ctx context.Context, userId string, attrs map[string]string) error
}

type UserUsecase struct {
	Repo UserRepo
}

type UserProfile struct {
	UserId        string
	Email         string
	CreatedAt     int64
	UpdatedAt     int64
	OfficialAttrs map[string]string
}

func NewUserUsecase(repo UserRepo) *UserUsecase {
	return &UserUsecase{Repo: repo}
}
