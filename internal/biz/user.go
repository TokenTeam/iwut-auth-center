package biz

import (
	"context"
	"fmt"
	v1 "iwut-auth-center/api/gen/go/auth_center/v1/error_reason"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"time"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/structpb"
)

// ---- Repo Interface (thin data access) ----

type UserRepo interface {
	UpdateUserPassword(ctx context.Context, uid string, oldPassword string, newPassword string) error
	DeleteUserAccount(ctx context.Context, uid string) error
	GetUserProfileWithFilter(ctx context.Context, uid string, keys []string) (*UserProfile, error)
	UpdateUserProfile(ctx context.Context, uid string, profileFields map[string]any) error
	GetUserProfileKeys(ctx context.Context, uid string) (*UserProfileKeys, error)
	GetUserClaimsWithFilter(ctx context.Context, uid string, keys []string) (map[string]any, error)
	RevokeUserConsent(ctx context.Context, uid string, clientId string, status string) error
	RemoveOAuthJTIsFormRedis(ctx context.Context, jtis []string) error

	UserExists(ctx context.Context, uid string) error
	GetDeveloperIdInfo(ctx context.Context, uid string) (developerId *string, lastUpdate *time.Time, err error)
	UpdateDeveloperId(ctx context.Context, uid string, developerId string) error
	UpsertUserConsent(ctx context.Context, uid string, clientId string, status string, internalVersion int32, optionalScopes []string) error
	DeleteUserConsentByStatus(ctx context.Context, uid string, clientId string, status string) error
}

// ---- Domain Types ----

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

// ---- Usecase ----

type UserUsecase struct {
	Repo                         UserRepo
	AppCenterUtil                *util.AppCenterUtil
	log                          *log.Helper
	officialInfoMemoryLimitation int64
}

func NewUserUsecase(repo UserRepo, appCenterUtil *util.AppCenterUtil, c *conf.Data, logger log.Logger) *UserUsecase {
	return &UserUsecase{
		Repo:                         repo,
		AppCenterUtil:                appCenterUtil,
		log:                          log.NewHelper(logger),
		officialInfoMemoryLimitation: c.GetMongodb().GetLimitations().GetUser().GetOfficialMemLimit() * 1024,
	}
}

// ---- Usecase Business Methods ----

func (uc *UserUsecase) UpdateUserProfile(ctx context.Context, uid string, attrs *structpb.Struct) error {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	attrsMap, length, err := util.StructToAnyMap(attrs)
	if err != nil {
		return err
	}
	if length > uc.officialInfoMemoryLimitation {
		l.Errorf("official info memory limitation exceeded: %d > %d", length, uc.officialInfoMemoryLimitation)
		return errors.New(413, string(v1.ErrorReason_OFFICIAL_INFO_MEMORY_LIMITATION_EXCEEDED), "official info memory limitation exceeded")
	}

	for k, v := range attrsMap {
		switch v.(type) {
		case map[string]any:
			return errors.BadRequest(string(v1.ErrorReason_INVALID_STRUCTURE), fmt.Sprintf("nested objects are not allowed in official attributes: key %q has object value", k))
		case []any:
			return errors.BadRequest(string(v1.ErrorReason_INVALID_STRUCTURE), fmt.Sprintf("array values are not allowed in official attributes: key %q has array value", k))
		}
	}

	return uc.Repo.UpdateUserProfile(ctx, uid, attrsMap)
}

func (uc *UserUsecase) SetUserDeveloperId(ctx context.Context, uid string, developerId string) error {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	if developerId == "" {
		return errors.BadRequest(string(v1.ErrorReason_INVALID_DEVELOPER_ID), "developerId cannot be empty")
	}
	for c := range developerId {
		if !((developerId[c] >= 'a' && developerId[c] <= 'z') || (developerId[c] >= 'A' && developerId[c] <= 'Z') ||
			(developerId[c] >= '0' && developerId[c] <= '9') ||
			developerId[c] == '-' || developerId[c] == '_') {
			return errors.BadRequest(string(v1.ErrorReason_INVALID_DEVELOPER_ID), "invalid developerId format: "+developerId)
		}
	}

	if err := uc.Repo.UserExists(ctx, uid); err != nil {
		return err
	}

	existingId, lastUpdate, err := uc.Repo.GetDeveloperIdInfo(ctx, uid)
	if err != nil {
		return err
	}

	if existingId != nil {
		if lastUpdate != nil {
			if time.Since(*lastUpdate) < 30*24*time.Hour {
				l.Infof("developerId can only be updated once every 30 days")
				return errors.BadRequest(string(v1.ErrorReason_UPDATE_DEVELOPER_ID_TOO_FREQUENTLY), "developerId can only be updated once every 30 days")
			}
		} else {
			l.Errorf("missing developer_id_updated_at for user with existing developerId: %s", uid)
		}
	}

	return uc.Repo.UpdateDeveloperId(ctx, uid, developerId)
}

func (uc *UserUsecase) UpdateUserConsent(ctx context.Context, uid string, clientId string, clientVersion int32, status string, optionalScopes []string, doCheck bool) error {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("UpdateUserConsent called with UserID: %s", uid)

	if err := uc.Repo.UserExists(ctx, uid); err != nil {
		return err
	}

	var applicationVersionInfo *util.ApplicationVersionInfo
	if doCheck {
		allowed, appVerInfo, err := uc.AppCenterUtil.GetApplicationVersionInfoWithUserCheck(ctx, clientId, uid, clientVersion)
		if err != nil {
			l.Errorf("failed to get client info: %v", err)
			return err
		}
		if appVerInfo == nil {
			l.Errorf("client not found: %s", clientId)
			return fmt.Errorf("client not found: %s with no error", clientId)
		}
		if !allowed {
			l.Errorf("user %s is not allowed to use client %s", uid, clientId)
		}
		scopeSet := make(map[string]struct{}, len(appVerInfo.OptionalScope))
		for _, v := range appVerInfo.OptionalScope {
			scopeSet[v] = struct{}{}
		}
		for _, v := range optionalScopes {
			if _, ok := scopeSet[v]; !ok {
				l.Errorf("invalid optional scope: %s", v)
				return errors.BadRequest(string(v1.ErrorReason_INVALID_SCOPE), "invalid optional scope: "+v)
			}
		}
		applicationVersionInfo = appVerInfo
		status = appVerInfo.Status
	} else {
		applicationVersionInfo = &util.ApplicationVersionInfo{
			Status:          status,
			InternalVersion: clientVersion,
		}
	}

	if err := uc.Repo.UpsertUserConsent(ctx, uid, clientId, applicationVersionInfo.Status, applicationVersionInfo.InternalVersion, optionalScopes); err != nil {
		l.Errorf("failed to upsert user consent: %v", err)
		return err
	}

	if applicationVersionInfo.Status == "STABLE" || applicationVersionInfo.Status == "GREY" {
		eraseStatus := "GREY"
		if applicationVersionInfo.Status == "GREY" {
			eraseStatus = "STABLE"
		}
		if err := uc.Repo.DeleteUserConsentByStatus(ctx, uid, clientId, eraseStatus); err != nil {
			l.Errorf("failed to erase user consent: %v", err)
			return err
		}
	}

	return nil
}
