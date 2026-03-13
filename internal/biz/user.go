package biz

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

type UserRepo interface {
	UpdateUserPassword(ctx context.Context, uid string, oldPassword string, newPassword string) error
	DeleteUserAccount(ctx context.Context, uid string) error
	GetUserProfileWithFilter(ctx context.Context, uid string, keys []string) (*UserProfile, error)
	UpdateUserProfile(ctx context.Context, uid string, attrs *structpb.Struct) error
	GetUserProfileKeys(ctx context.Context, uid string) (*UserProfileKeys, error)
	GetUserClaimsWithFilter(ctx context.Context, uid string, keys []string) (map[string]any, error)
	UpdateUserConsent(ctx context.Context, uid string, clientId string, clientVersion int32, status string, optionalScopes []string, doCheck bool) error
	SetUserDeveloperId(ctx context.Context, uid string, developerId string) error
	RevokeUserConsent(ctx context.Context, uid string, clientId string, status string) error
	RemoveOAuthJTIsFormRedis(ctx context.Context, jtis []string) error
}

type UserUsecase struct {
	Repo UserRepo
}

type UserProfile struct {
	UserId        string
	Email         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	OfficialAttrs map[string]any
}

type UserProfileKeys struct {
	BaseKeys         []string
	ExtraProfileKeys []string
}

func NewUserUsecase(repo UserRepo) *UserUsecase {
	return &UserUsecase{Repo: repo}
}
