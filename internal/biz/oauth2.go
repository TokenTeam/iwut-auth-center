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
	"github.com/samber/lo"
)

// ---- Domain Types ----

type UserConsentRecord struct {
	AgreedVersion int32
	OptionalScope []string
	Type          string
}

type ResolvedConsentAccess struct {
	Allowed                bool
	ApplicationVersionInfo *util.ApplicationVersionInfo
	BasicScope             []string
	OptionalScope          []string
}

type CodeInfo struct {
	UserId              string `json:"user_id"`
	ClientId            string `json:"client_id"`
	ResponseType        string `json:"response_type"`
	InternalVersion     int32  `json:"internal_version"`
	Scope               string `json:"scope"`
	RedirectUri         string `json:"redirect_uri"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	CreatedAt           int64  `json:"created_at"`
	Status              string `json:"status"`
}

type Oauth2UserProfile struct {
	OfficialAttrs   map[string]any     `json:"official_attrs"`
	StorageKeyValue map[string]*string `json:"storage_key_value"`
}

// ---- Pure Domain Functions ----

func NormalizeUniqueScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	result := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func IntersectScopesByOrder(reference []string, granted []string) []string {
	if len(reference) == 0 || len(granted) == 0 {
		return nil
	}
	grantedSet := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		grantedSet[scope] = struct{}{}
	}
	result := make([]string, 0, len(reference))
	seen := make(map[string]struct{}, len(reference))
	for _, scope := range reference {
		if _, ok := grantedSet[scope]; !ok {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func BasicScopeCovered(grantedBasicScope []string, targetBasicScope []string) bool {
	if len(targetBasicScope) == 0 {
		return true
	}
	grantedSet := make(map[string]struct{}, len(grantedBasicScope))
	for _, scope := range grantedBasicScope {
		grantedSet[scope] = struct{}{}
	}
	for _, scope := range targetBasicScope {
		if _, ok := grantedSet[scope]; !ok {
			return false
		}
	}
	return true
}

// ScopeIntersection intersects multiple scope slices (preserving the order of the
// first) and strips the "read__" prefix (first 6 chars) from each surviving scope.
func ScopeIntersection(scopes ...[]string) []string {
	if len(scopes) == 0 {
		return nil
	}
	result := scopes[0]
	for i := 1; i < len(scopes); i++ {
		result = lo.Intersect(result, scopes[i])
	}
	return lo.Map(result, func(s string, _ int) string {
		return s[6:]
	})
}

func ResolveTestConsentAccess(target *util.ApplicationVersionInfo, consents []UserConsentRecord) (*ResolvedConsentAccess, error) {
	for _, consent := range consents {
		if consent.Type != "TEST" || consent.AgreedVersion != target.InternalVersion {
			continue
		}
		return &ResolvedConsentAccess{
			Allowed:                true,
			ApplicationVersionInfo: target,
			BasicScope:             NormalizeUniqueScopes(target.BasicScope),
			OptionalScope:          IntersectScopesByOrder(target.OptionalScope, consent.OptionalScope),
		}, nil
	}
	return nil, errors.Forbidden(v1.ErrorReason_USER_DENIED.String(), "user consent not found for this version")
}

// ---- Repo Interface (thin data access) ----

type Oauth2Repo interface {
	SetCodeInfo(ctx context.Context, code string, codeInfo *CodeInfo) error
	GetCodeInfo(ctx context.Context, code string) (*CodeInfo, error)
	EraseCodeInfo(ctx context.Context, code string) error

	LoadUserConsentRecords(ctx context.Context, uid string, clientId string) ([]UserConsentRecord, error)
	GetUserConsentJTIs(ctx context.Context, uid string, clientId string, status string) ([]string, error)
	UpdateUserConsentJTIs(ctx context.Context, uid string, clientId string, status string, tokenIDs []string) error
	AllowJTIs(ctx context.Context, jtis []string) error
	CheckUserConsentExists(ctx context.Context, uid string, clientId string) error

	GetUserStorageData(ctx context.Context, uid string, applicationId string, storageKeys []string) (map[string]*string, error)
	SetUserStorageData(ctx context.Context, uid string, applicationId string, storageKeyValues map[string]string, memLimit int64) error
}

// ---- Usecase ----

const maxJTIsPerConsent = 5

type Oauth2Usecase struct {
	Repo                       Oauth2Repo
	UserRepo                   UserRepo
	AppCenterUtil              *util.AppCenterUtil
	log                        *log.Helper
	oauth2InfoMemoryLimitation int64
}

func NewOauth2Usecase(repo Oauth2Repo, userRepo UserRepo, appCenterUtil *util.AppCenterUtil, c *conf.Data, logger log.Logger) *Oauth2Usecase {
	return &Oauth2Usecase{
		Repo:                       repo,
		UserRepo:                   userRepo,
		AppCenterUtil:              appCenterUtil,
		log:                        log.NewHelper(logger),
		oauth2InfoMemoryLimitation: c.GetMongodb().GetLimitations().GetUser().GetOauth2MemLimit(),
	}
}

// ---- Usecase Business Methods ----

func (uc *Oauth2Usecase) CheckGetCodeAndSetTypeRequest(ctx context.Context, codeInfo *CodeInfo) (bool, error) {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if codeInfo.Scope != "read" {
		return false, errors.BadRequest(v1.ErrorReason_INVALID_SCOPE.String(), "unsupported scope")
	}
	if codeInfo.ResponseType != "code" {
		return false, errors.BadRequest(v1.ErrorReason_INVALID_RESPONSE_TYPE.String(), "unsupported response_type")
	}

	l.Debugf("CheckGetCodeAndSetTypeRequest userId: %s, codeInfo: %+v", codeInfo.UserId, codeInfo)

	ok, applicationVersionInfo, err := uc.CheckUserPermissionAndGetApplicationVersionInfo(ctx, codeInfo.UserId, codeInfo.ClientId, codeInfo.InternalVersion)
	if !ok {
		return false, err
	}
	if applicationVersionInfo == nil {
		return false, fmt.Errorf("CheckGetCodeAndSetTypeRequest returned nil applicationVersionInfo for clientId: %s, internalVersion: %d", codeInfo.ClientId, codeInfo.InternalVersion)
	}

	applicationInfo, err := uc.AppCenterUtil.GetApplicationInfo(ctx, codeInfo.ClientId)
	if err != nil {
		l.Warnf("CheckGetCodeAndSetTypeRequest err: %+v", err)
		return false, err
	}
	if applicationInfo == nil {
		return false, fmt.Errorf("CheckGetCodeAndSetTypeRequest GetApplicationInfo returned nil for clientId: %s", codeInfo.ClientId)
	}

	if lo.Contains(applicationInfo.RedirectUri, codeInfo.RedirectUri) {
		codeInfo.Status = applicationVersionInfo.Status
		return true, nil
	}

	return false, errors.BadRequest(v1.ErrorReason_REDIRECT_URI_MISMATCH.String(), "redirect_uri mismatch")
}

func (uc *Oauth2Usecase) resolveUserConsentAccess(ctx context.Context, uid string, clientId string, internalVersion int32) (*ResolvedConsentAccess, error) {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	allowed, applicationVersionInfo, err := uc.AppCenterUtil.GetApplicationVersionInfoWithUserCheck(ctx, clientId, uid, internalVersion)
	if err != nil {
		l.Errorf("resolveUserConsentAccess GetApplicationVersionInfoWithUserCheck failed: %v", err)
		return nil, err
	}
	if applicationVersionInfo == nil {
		return nil, fmt.Errorf("resolveUserConsentAccess returned nil applicationVersionInfo for clientId: %s, internalVersion: %d", clientId, internalVersion)
	}
	if !allowed {
		return &ResolvedConsentAccess{
			Allowed:                false,
			ApplicationVersionInfo: applicationVersionInfo,
		}, errors.Forbidden(v1.ErrorReason_PERMISSION_DENIED.String(), "user permission denied")
	}
	if applicationVersionInfo.Status != "STABLE" && applicationVersionInfo.Status != "GREY" && applicationVersionInfo.Status != "TEST" {
		return nil, errors.BadRequest(v1.ErrorReason_INVALID_APPLICATION_VERSION_STATUS.String(), "an application with invalid status trying to access user official profile")
	}

	consents, err := uc.Repo.LoadUserConsentRecords(ctx, uid, clientId)
	if err != nil {
		return nil, err
	}

	switch applicationVersionInfo.Status {
	case "TEST":
		return ResolveTestConsentAccess(applicationVersionInfo, consents)
	case "STABLE", "GREY":
		return uc.resolveStableGreyConsentAccess(ctx, clientId, applicationVersionInfo, consents)
	default:
		return nil, errors.BadRequest(v1.ErrorReason_INVALID_APPLICATION_VERSION_STATUS.String(), "an application with invalid status trying to access user official profile")
	}
}

func (uc *Oauth2Usecase) resolveStableGreyConsentAccess(ctx context.Context, clientId string, target *util.ApplicationVersionInfo, consents []UserConsentRecord) (*ResolvedConsentAccess, error) {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	stableGreyConsents := make([]UserConsentRecord, 0, len(consents))
	for _, consent := range consents {
		if consent.Type == "STABLE" || consent.Type == "GREY" {
			stableGreyConsents = append(stableGreyConsents, consent)
		}
	}
	if len(stableGreyConsents) == 0 {
		return nil, errors.Forbidden(v1.ErrorReason_USER_DENIED.String(), "user consent not found")
	}

	for _, consent := range stableGreyConsents {
		if consent.AgreedVersion != target.InternalVersion {
			continue
		}
		return &ResolvedConsentAccess{
			Allowed:                true,
			ApplicationVersionInfo: target,
			BasicScope:             NormalizeUniqueScopes(target.BasicScope),
			OptionalScope:          IntersectScopesByOrder(target.OptionalScope, consent.OptionalScope),
		}, nil
	}

	var bestCompatibleConsent *UserConsentRecord
	for i := range stableGreyConsents {
		consent := &stableGreyConsents[i]
		consentVersionInfo, err := uc.AppCenterUtil.GetApplicationVersionInfo(ctx, clientId, consent.AgreedVersion)
		if err != nil {
			l.Errorf("resolveStableGreyConsentAccess GetApplicationVersionInfo error: %v", err)
			return nil, err
		}
		if consentVersionInfo == nil {
			l.Warnf("resolveStableGreyConsentAccess skip missing version info for clientId: %s, agreedVersion: %d", clientId, consent.AgreedVersion)
			continue
		}
		if !BasicScopeCovered(consentVersionInfo.BasicScope, target.BasicScope) {
			continue
		}
		if bestCompatibleConsent == nil || consent.AgreedVersion > bestCompatibleConsent.AgreedVersion {
			bestCompatibleConsent = consent
		}
	}
	if bestCompatibleConsent == nil {
		return nil, errors.Forbidden(v1.ErrorReason_USER_DENIED.String(), "user client version outdated")
	}

	return &ResolvedConsentAccess{
		Allowed:                true,
		ApplicationVersionInfo: target,
		BasicScope:             NormalizeUniqueScopes(target.BasicScope),
		OptionalScope:          IntersectScopesByOrder(target.OptionalScope, bestCompatibleConsent.OptionalScope),
	}, nil
}

func (uc *Oauth2Usecase) CheckUserPermissionAndGetApplicationVersionInfo(ctx context.Context, userId string, clientId string, internalVersion int32) (bool, *util.ApplicationVersionInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("CheckUserPermissionAndGetApplicationVersionInfo userId: %s, clientId: %s", userId, clientId)

	resolvedAccess, err := uc.resolveUserConsentAccess(ctx, userId, clientId, internalVersion)
	if err != nil {
		if resolvedAccess != nil {
			return false, resolvedAccess.ApplicationVersionInfo, err
		}
		return false, nil, err
	}
	if resolvedAccess == nil || resolvedAccess.ApplicationVersionInfo == nil {
		return false, nil, fmt.Errorf("resolveUserConsentAccess returned nil for userId: %s, clientId: %s, internalVersion: %d", userId, clientId, internalVersion)
	}
	return resolvedAccess.Allowed, resolvedAccess.ApplicationVersionInfo, nil
}

func (uc *Oauth2Usecase) GetUserOfficialProfile(ctx context.Context, uid string, clientId string, internalVersion int32, scopes []string) (map[string]any, error) {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetUserOfficialProfile uid: %s, clientId: %s, internalVersion: %d", uid, clientId, internalVersion)

	resolvedAccess, err := uc.resolveUserConsentAccess(ctx, uid, clientId, internalVersion)
	if err != nil {
		return nil, err
	}
	if resolvedAccess == nil || !resolvedAccess.Allowed || resolvedAccess.ApplicationVersionInfo == nil {
		return nil, errors.Forbidden(v1.ErrorReason_PERMISSION_DENIED.String(), "user permission denied")
	}

	readScopes := ScopeIntersection(scopes, resolvedAccess.BasicScope)
	if len(readScopes) == 0 {
		return map[string]any{}, nil
	}

	userProfile, err := uc.UserRepo.GetUserProfileWithFilter(ctx, uid, readScopes)
	if err != nil {
		l.Errorf("GetUserOfficialProfile GetUserProfileWithFilter error: %v", err)
		return nil, err
	}

	officialScope := map[string]any{}
	for _, k := range readScopes {
		switch k {
		case "uid":
			officialScope[k] = userProfile.UserId
		case "email":
			officialScope[k] = userProfile.Email
		case "created_at":
			officialScope[k] = userProfile.CreatedAt
		case "updated_at":
			officialScope[k] = userProfile.UpdatedAt
		default:
			if v, ok := userProfile.OfficialAttrs[k]; ok {
				officialScope[k] = v
			} else {
				officialScope[k] = nil
			}
		}
	}
	return officialScope, nil
}

func (uc *Oauth2Usecase) InsertJTIToUserConsents(ctx context.Context, uid string, clientId string, jti string, status string) error {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("InsertJTIToUserConsents userId: %s, clientId: %s, jti: %s", uid, clientId, jti)

	tokenIDs, err := uc.Repo.GetUserConsentJTIs(ctx, uid, clientId, status)
	if err != nil {
		return err
	}

	tokenIDs = append(tokenIDs, jti)

	if err := uc.Repo.AllowJTIs(ctx, []string{jti}); err != nil {
		l.Errorf("AllowJTIs error: %v", err)
		return err
	}

	var toBlock []string
	if len(tokenIDs) > maxJTIsPerConsent {
		overflow := len(tokenIDs) - maxJTIsPerConsent
		toBlock = append(toBlock, tokenIDs[:overflow]...)
		tokenIDs = tokenIDs[overflow:]
	}

	if err := uc.Repo.UpdateUserConsentJTIs(ctx, uid, clientId, status, tokenIDs); err != nil {
		l.Errorf("UpdateUserConsentJTIs error: %v", err)
		return err
	}

	if len(toBlock) > 0 {
		if err := uc.UserRepo.RemoveOAuthJTIsFormRedis(ctx, toBlock); err != nil {
			l.Errorf("RemoveOAuthJTIsFormRedis error: %v", err)
			return err
		}
	}
	return nil
}

func (uc *Oauth2Usecase) GetUserProfile(ctx context.Context, uid string, clientId string, storageKeys []string) (map[string]*string, error) {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("GetUserProfile userId: %s, clientId: %s", uid, clientId)

	applicationInfo, err := uc.AppCenterUtil.GetApplicationInfo(ctx, clientId)
	if err != nil {
		l.Errorf("GetApplicationInfo failed: %v", err)
		return nil, err
	}
	if applicationInfo == nil {
		return nil, fmt.Errorf("GetApplicationInfo returned nil for clientId: %s", clientId)
	}

	if err := uc.Repo.CheckUserConsentExists(ctx, uid, clientId); err != nil {
		return nil, err
	}

	for _, s := range storageKeys {
		if !util.IsASCIIAlphaNumDashUnderscore(s) {
			return nil, errors.BadRequest(v1.ErrorReason_INVALID_KEY_NAME.String(), fmt.Sprintf("invalid storage key '%s'", s))
		}
	}

	return uc.Repo.GetUserStorageData(ctx, uid, applicationInfo.Id, storageKeys)
}

func (uc *Oauth2Usecase) SetUserProfile(ctx context.Context, uid string, clientId string, storageKeyValues map[string]string) error {
	l := log.NewHelper(log.WithContext(ctx, uc.log.Logger()))

	if len(storageKeyValues) > 1000 {
		return errors.BadRequest(v1.ErrorReason_TOO_MANY_KEYS.String(), "too many storage keys to set")
	}

	var totalLength int64
	for k, v := range storageKeyValues {
		if !util.IsASCIIAlphaNumDashUnderscore(k) {
			return errors.BadRequest(v1.ErrorReason_INVALID_KEY_NAME.String(), fmt.Sprintf("invalid storage key '%s'", k))
		}
		totalLength += int64(len(k) + len(v))
	}
	if totalLength > uc.oauth2InfoMemoryLimitation {
		return errors.New(413, v1.ErrorReason_OAUTH2_INFO_MEMORY_LIMITATION_EXCEEDED.String(), "oauth2 info memory limitation exceeded")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("SetUserProfile userId: %s clientId: %s", uid, clientId)

	applicationInfo, err := uc.AppCenterUtil.GetApplicationInfo(ctx, clientId)
	if err != nil {
		l.Errorf("GetApplicationInfo failed: %v", err)
		return err
	}
	if applicationInfo == nil {
		return fmt.Errorf("GetApplicationInfo returned nil for clientId: %s", clientId)
	}

	if err := uc.Repo.CheckUserConsentExists(ctx, uid, clientId); err != nil {
		return err
	}

	return uc.Repo.SetUserStorageData(ctx, uid, applicationInfo.Id, storageKeyValues, uc.oauth2InfoMemoryLimitation)
}
