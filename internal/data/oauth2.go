package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/util"
	"strings"
	"time"

	kratosErrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-redis/redis/v8"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type oauth2Repo struct {
	data                       *Data
	log                        *log.Helper
	appUsecase                 *biz.AppUsecase
	userCollection             *mongo.Collection
	userConsentsCollection     *mongo.Collection
	refreshTokenLifeSpan       time.Duration
	oauth2InfoMemoryLimitation int64
}

// NewOauth2Repo constructs an oauth2 repository backed by MongoDB and Redis.
// Behavior:
// - Binds collections `user` and `user_consents` and reads configuration limits.
// - Does not modify DB schema or create indexes.
// Parameters:
// - data: initialized *Data with mongo/redis clients.
// - c: configuration used to read DB name and memory limits.
// - jwtConf: JWT related configuration (used to determine refresh token lifetime).
// - appUsecase: used to query client metadata when needed.
// - logger: logger for repository.
// Returns:
// - biz.Oauth2Repo: repository implementation.
func NewOauth2Repo(data *Data, c *conf.Data, jwtConf *conf.Jwt, appUsecase *biz.AppUsecase, logger log.Logger) biz.Oauth2Repo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	userConsentsCollection := data.mongo.Database(dbName).Collection("user_consents")

	return &oauth2Repo{
		data:                       data,
		log:                        log.NewHelper(logger),
		appUsecase:                 appUsecase,
		userCollection:             usersCollection,
		userConsentsCollection:     userConsentsCollection,
		refreshTokenLifeSpan:       time.Duration(jwtConf.GetRefreshTokenLifeSpan()) * time.Second,
		oauth2InfoMemoryLimitation: c.GetMongodb().GetLimitations().GetUser().GetOauth2MemLimit(),
	}
}

// CheckGetCodeRequest validates an incoming authorization code request.
// Behavior:
// - Validates codeInfo.ResponseType and Scope are supported.
// - Ensures the user has permission for the client via CheckUserPermission.
// - Verifies the provided redirect_uri matches the client metadata from AppCenter.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - codeInfo: authorization request metadata (userId, clientId, redirectUri, scope, responseType).
// Returns:
// - bool: true if request is valid, false otherwise.
// - error: kratos error describing why the request is invalid or wrapped internal errors.
func (r *oauth2Repo) CheckGetCodeRequest(ctx context.Context, codeInfo *biz.CodeInfo) (bool, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	userId := codeInfo.UserId
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if codeInfo.Scope != "read" {
		return false, kratosErrors.BadRequest("", "unsupported scope")
	}

	if codeInfo.ResponseType != "code" {
		return false, kratosErrors.BadRequest("", "unsupported response_type")
	}

	l.Debugf("CheckGetCodeRequest userId: %s, codeInfo: %+v", userId, codeInfo)

	if ok, err := r.CheckUserPermission(ctx, userId, codeInfo.ClientId); !ok {
		return false, err
	}
	clientInfo, err := r.appUsecase.Repo.GetClientInfo(ctx, codeInfo.ClientId)
	if err != nil {
		l.Errorf("GetClientInfo failed: %v", err)
		return false, err
	}
	if clientInfo == nil {
		return false, kratosErrors.BadRequest("", "invalid client_id")
	}
	for _, url := range clientInfo.RedirectUri {
		if codeInfo.RedirectUri == url {
			return true, nil
		}
	}
	return false, kratosErrors.BadRequest("", "redirect_uri mismatch")
}

// SetCodeInfo stores an authorization code and its associated metadata in Redis.
// Behavior:
// - Serializes the provided CodeInfo to JSON and writes it to Redis with a short TTL.
// - Uses a 5s context timeout for Redis calls.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - code: authorization code string.
// - codeInfo: metadata associated with the code.
// Returns:
// - error: non-nil on serialization or Redis errors.
func (r *oauth2Repo) SetCodeInfo(ctx context.Context, code string, codeInfo *biz.CodeInfo) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	userId := codeInfo.UserId
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("SetCodeInfo userId: %s, code: %s, codeInfo: %+v", userId, code, codeInfo)

	err := r.cacheCodeInfo(ctx, code, codeInfo)
	if err != nil {
		l.Errorf("cacheCodeInfo error: %v", err)
		return err
	}
	return nil
}

// GetCodeInfo reads a code's metadata from Redis.
// Behavior:
// - Reads JSON blob from Redis and unmarshals into biz.CodeInfo.
// - Returns (nil, nil) when the code is not present (expired or never set).
// - Uses a 5s context timeout for Redis operations.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - code: authorization code string to look up.
// Returns:
// - *biz.CodeInfo: the stored metadata when present.
// - error: non-nil on Redis/errors or JSON unmarshal failures.
func (r *oauth2Repo) GetCodeInfo(ctx context.Context, code string) (*biz.CodeInfo, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("GetCodeInfo code: %s", code)
	codeInfo, err := r.getCodeInfoFromCache(ctx, code)
	if err != nil {
		l.Errorf("getCodeInfoFromCache error: %v", err)
		return nil, err
	}
	if codeInfo == nil {
		return nil, nil
	}
	return codeInfo, nil
}

// EraseCodeInfo removes a stored authorization code from Redis (makes the code invalid).
// Behavior:
// - Deletes the redis key associated with the code; logs and returns Redis errors.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - code: authorization code to remove.
// Returns:
// - error: non-nil on Redis errors.
func (r *oauth2Repo) EraseCodeInfo(ctx context.Context, code string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("EraseCodeInfo code: %s", code)
	err := r.data.redis.Del(ctx, GetRedisKey("oauth2_code", code)).Err()
	if err != nil {
		l.Errorf("EraseCodeInfo error: %v", err)
		return err
	}
	return nil
}

// InsertJTIToUserConsents appends a JTI to the user's consent record and manages
// allowed token tracking.
// Behavior:
//   - Reads the user_consents document for {user_id, client_id} and appends the new jti
//     to the token_id array.
//   - Writes the new JTI to Redis allowlist via AllowJTIs so refresh tokens can be validated quickly.
//   - Keeps at most 5 JTIs per consent; older ids beyond the limit are removed from
//     the document and scheduled to be removed from Redis via RemoveJTIsFormRedis.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId, clientId: identifiers locating the consent record.
// - jti: token identifier to add.
// Returns:
// - error: kratos NotFound when consent missing; wrapped DB/Redis errors otherwise.
func (r *oauth2Repo) InsertJTIToUserConsents(ctx context.Context, userId string, clientId string, jti string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("InsertJTIToUserConsents userId: %s, clientId: %s, jti: %s", userId, clientId, jti)

	collection := r.userConsentsCollection
	filter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
	}

	// 先查出现有的 token_id 列表
	var doc struct {
		TokenID []string `bson:"token_id"`
	}
	err := collection.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			l.Errorf("FindOne error: %v", err)
			return kratosErrors.NotFound("404", "user consent not found")
		}
		l.Errorf("InsertJTIToUserConsents FindOne error: %v", err)
		return err
	}

	// 追加当前 jti
	tokenIDs := append(doc.TokenID, jti)

	if err := r.AllowJTIs(ctx, []string{jti}); err != nil {
		l.Errorf("AllowJTIs error: %v", err)
		return err
	}

	// 如果超过 5 个，则截断为保留最后 5 个，其余加入阻止列表
	var toBlock []string
	if len(tokenIDs) > 5 {
		// 需要阻止的旧 token（从最早开始）
		overflow := len(tokenIDs) - 5
		toBlock = append(toBlock, tokenIDs[:overflow]...)
		tokenIDs = tokenIDs[overflow:]
	}

	// 更新 MongoDB 中的 token_id 数组
	update := bson.M{
		"$set": bson.M{
			"token_id": tokenIDs,
		},
	}
	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		l.Errorf("InsertJTIToUserConsents UpdateOne error: %v", err)
		return err
	}

	if len(toBlock) > 0 {
		if err := r.RemoveJTIsFormRedis(ctx, toBlock); err != nil {
			l.Errorf("RemoveJTIsFormRedis error: %v", err)
			return err
		}
	}
	return nil
}

// RevokeUserConsent atomically revokes a user's consent for a client.
// Behavior:
//   - Atomically reads and clears the `token_id` array from the `user_consents` document
//     using FindOneAndUpdate and returns the pre-update value.
//   - Removes any corresponding allowed token keys from Redis (via RemoveJTIsFormRedis).
//   - Uses short timeouts for DB/Redis operations and logs failures.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: user identifier.
// - clientId: client identifier.
// Returns:
// - error: kratos.NotFound if user consent does not exist; wrapped DB/Redis errors otherwise.
func (r *oauth2Repo) RevokeUserConsent(ctx context.Context, userId string, clientId string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("RevokeUserConsent userId: %s, clientId: %s", userId, clientId)

	collection := r.userConsentsCollection
	filter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
	}

	// 原子地读取并清空 token_id，使用 FindOneAndUpdate 返回修改前的文档
	update := bson.M{"$set": bson.M{"token_id": []string{}}}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.Before)
	var oldDoc struct {
		TokenID []string `bson:"token_id"`
	}
	res := collection.FindOneAndUpdate(ctx, filter, update, opts)
	if err := res.Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			l.Errorf("RevokeUserConsent FindOneAndUpdate no document: %v", err)
			return kratosErrors.NotFound("404", "user consent not found")
		}
		l.Errorf("RevokeUserConsent FindOneAndUpdate error: %v", err)
		return err
	}
	if err := res.Decode(&oldDoc); err != nil {
		l.Errorf("RevokeUserConsent decode error: %v", err)
		return err
	}

	// 从 Redis 中删除对应的 allowed_tokens 键（如果有）
	if len(oldDoc.TokenID) > 0 {
		if err := r.RemoveJTIsFormRedis(ctx, oldDoc.TokenID); err != nil {
			l.Errorf("RevokeUserConsent RemoveJTIsFormRedis error: %v", err)
			return err
		}
	}
	return nil
}

// GetUserProfile returns the OAuth2 user profile visible to a client.
// Behavior:
//   - Validates the client and that the client-version matches the user's agreed version.
//   - Computes the readable scopes as intersection of requested scopes and granted scopes
//     (basic + optional), rejects requests for scopes not granted or for sensitive scopes like `password`.
//   - Projects only the requested readable fields from the `user` collection and
//     converts BSON values to Go types via util.ConvertBSONValueToGOType.
//   - Also resolves storage keys into namespaced fields (clientName__key) and returns
//     both official attributes and storage key values.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: hex string of the user's MongoDB ObjectID.
// - clientId: client identifier.
// - scopes: list of requested scope keys (base scope names, not prefixed).
// - storageKeys: list of storage key names the client wants to read.
// Returns:
// - *biz.Oauth2UserProfile: contains OfficialAttrs (key->value) and StorageKeyValue (key->*string).
// - error: biz.UserNotFoundError when the user is missing; kratos errors for permission problems; wrapped DB errors otherwise.
func (r *oauth2Repo) GetUserProfile(ctx context.Context, userId string, clientId string, scopes []string, storageKeys []string) (*biz.Oauth2UserProfile, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("GetUserProfile userId: %s, clientId: %s", userId, clientId)

	clientInfo, err := r.appUsecase.Repo.GetClientInfo(ctx, clientId)
	if err != nil {
		l.Errorf("GetClientInfo failed: %v", err)
		return nil, err
	}
	if clientInfo == nil {
		return nil, kratosErrors.BadRequest("", "get client info failed")
	}

	collection := r.userConsentsCollection
	filter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
	}

	var result struct {
		OptionalScope []string `bson:"optional_scope"`
		AgreedVersion string   `bson:"agreed_version"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		l.Errorf("GetUserProfile FindOne error: %v", err)
		return nil, err
	}
	if clientInfo.Version != result.AgreedVersion {
		l.Errorf("GetUserProfile client version outdated: %s != %s", clientInfo.Version, result.AgreedVersion)
		return nil, kratosErrors.Forbidden("", "client version outdated")
	}

	// 在此处计算可读 scopes：先取并集 clientInfo.BasicScope U result.OptionalScope，然后与 baseScopes 做交集
	unionMap := make(map[string]struct{})
	for _, s := range clientInfo.BasicScope {
		if strings.HasPrefix(s, "read__") {
			unionMap[s[6:]] = struct{}{}
		}
	}
	for _, s := range result.OptionalScope {
		if strings.HasPrefix(s, "read__") {
			unionMap[s[6:]] = struct{}{}
		}
	}

	// 交集 — 为了保持 baseScopes 的顺序，遍历 baseScopes 并检查是否在 unionMap 中
	var readableScopes []string
	seen := make(map[string]struct{})
	for _, s := range scopes {
		if _, ok := unionMap[s]; ok {
			if _, dup := seen[s]; !dup {
				readableScopes = append(readableScopes, s)
				seen[s] = struct{}{}
			}
		} else {
			l.Errorf("GetUserProfile scope '%s' not granted", s)
			return nil, kratosErrors.Forbidden("", fmt.Sprintf("permission denied for scope '%s'", s))
		}
	}

	if _, ok := seen["password"]; ok {
		l.Errorf("GetUserProfile try to read sensitive scope 'password'")
		return nil, kratosErrors.Forbidden("", "permission denied for scope 'password'")
	}

	for _, key := range storageKeys {
		for _, storageKey := range clientInfo.StorageKeys {
			if key == storageKey {
				readableScopes = append(readableScopes, clientInfo.Name+"__"+key)
			}
		}
	}

	l.Debugf("GetUserProfile readableScopes: %+v", readableScopes)

	// convert userId to ObjectID for querying user collection
	uid, err := bson.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return nil, fmt.Errorf("invalid userId format: %s", userId)
	}

	// --- 新版：直接从 userCollection 中按 readableScopes 投影字段 ---
	// 始终包含 _id 以便返回 UserId
	proj := bson.D{}
	for _, s := range readableScopes {
		proj = append(proj, bson.E{Key: s, Value: 1})
	}

	userColl := r.userCollection
	pipeline := mongo.Pipeline{
		{{"$match", bson.D{{"_id", uid}}}},
		{{"$project", proj}},
	}

	cur, err := userColl.Aggregate(ctx, pipeline)
	if err != nil {
		l.Errorf("GetUserProfile aggregate user error: %v", err)
		return nil, err
	}
	defer func() { _ = cur.Close(ctx) }()

	if !cur.Next(ctx) {
		if err := cur.Err(); err != nil {
			l.Errorf("GetUserProfile cursor error: %v", err)
			return nil, err
		}
		// 用户不存在
		return nil, biz.UserNotFoundError
	}

	var doc bson.M
	if err := cur.Decode(&doc); err != nil {
		l.Errorf("GetUserProfile decode user doc error: %v", err)
		return nil, err
	}

	officialScope := map[string]any{}
	storageKeyValue := map[string]*string{}
	for _, k := range scopes {
		// check if k in doc
		if val, ok := doc[k]; ok {
			conv, err := util.ConvertBSONValueToGOType(val)
			if err != nil {
				l.Errorf("GetUserProfile scope '%s' has unsupported type: %v", k, err)
				return nil, kratosErrors.InternalServer("", fmt.Sprintf("scope '%s' has unsupported type", k))
			}
			officialScope[k] = conv
		} else {
			officialScope[k] = nil
		}
	}
	for _, k := range storageKeys {
		fullKey := clientInfo.Name + "__" + k
		if val, ok := doc[fullKey]; ok {
			conv, err := util.ConvertBSONValueToGOType(val)
			if err != nil {
				l.Errorf("GetUserProfile storage key '%s' has unsupported type: %v", fullKey, err)
				return nil, kratosErrors.InternalServer("", fmt.Sprintf("storage key '%s' is invalid", k))
			}
			if conv == nil {
				storageKeyValue[k] = nil
			} else if s, ok := conv.(string); ok {
				storageKeyValue[k] = &s
			} else {
				l.Errorf("GetUserProfile storage key '%s' is invalid type: %T", fullKey, conv)
				return nil, kratosErrors.InternalServer("", fmt.Sprintf("storage key '%s' is invalid", k))
			}
		} else {
			storageKeyValue[k] = nil
		}
	}
	return &biz.Oauth2UserProfile{
		OfficialAttrs:   officialScope,
		StorageKeyValue: storageKeyValue,
	}, nil
}

// SetUserProfile incrementally updates user's storage key/value pairs for a client.
// Behavior:
// - Validates userId format and checks basic limits: max keys (20) and total memory usage against oauth2InfoMemoryLimitation.
// - Validates the client exists and that the user's consent record agreed_version matches the client version; rejects when version mismatches.
// - If storageKeyValues contain keys not already known by the client, attempts to update the client's StorageKeys via SetClientInfoStorageKeys and re-checks client metadata; if keys remain invalid, returns an error.
// - Writes values into the user document using namespaced field names <clientName>__<key> via a single $set update.
// - Uses short timeouts (5s) for DB/Redis calls and logs failures.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: hex string of the user's MongoDB ObjectID.
// - clientId: client identifier.
// - storageKeyValues: map of storage key -> value to set (will be namespaced by client name).
//
// Returns:
// - error: kratos.BadRequest for invalid input/limits; kratos.Forbidden when client version mismatches; biz.OAuth2InfoMemoryLimitationExceededError when memory limit exceeded; wrapped DB/Redis errors for persistence failures.
func (r *oauth2Repo) SetUserProfile(ctx context.Context, userId string, clientId string, storageKeyValues map[string]string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	uid, err := bson.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}

	if len(storageKeyValues) > 20 {
		l.Errorf("too many storage keys to set: %d", len(storageKeyValues))
		return kratosErrors.BadRequest("", "too many storage keys to set")
	}

	if count := int64(func(m map[string]string) int {
		total := 0
		for k, v := range m {
			total += len(k) + len(v)
		}
		return total
	}(storageKeyValues)); count > r.oauth2InfoMemoryLimitation {
		l.Errorf("oauth info memory limitation exceeded: %d > %d", count, r.oauth2InfoMemoryLimitation)
		return biz.OAuth2InfoMemoryLimitationExceededError
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("SetUserProfile userId: %s clientId: %s", userId, clientId)

	clientInfo, err := r.appUsecase.Repo.GetClientInfo(ctx, clientId)
	if err != nil {
		l.Errorf("GetClientInfo failed: %v", err)
		return err
	}
	if clientInfo == nil {
		return kratosErrors.BadRequest("", "get client info failed")
	}

	collection := r.userConsentsCollection
	filter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
	}
	var result struct {
		AgreedVersion string `bson:"agreed_version"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		l.Errorf("GetClientInfo failed: %v", err)
		return err
	}
	if clientInfo.Version != result.AgreedVersion {
		l.Errorf("SetUserProfile client version outdated: %s != %s", clientInfo.Version, result.AgreedVersion)
		return kratosErrors.Forbidden("", "client version outdated")
	}

	var newKeys []string
	for k := range storageKeyValues {
		occurredKey := false
		for i := range clientInfo.StorageKeys {
			if k == clientInfo.StorageKeys[i] {
				occurredKey = true
			}
		}
		if !occurredKey {
			newKeys = append(newKeys, k)
		}
	}
	if len(newKeys) > 0 {
		if len(newKeys)+len(clientInfo.StorageKeys) > 20 {
			l.Errorf("SetUserProfile exceed storage keys limitation after adding new keys")
			return kratosErrors.BadRequest("", "exceed storage keys limitation after adding new keys")
		}
		err = r.SetClientInfoStorageKeys(ctx, clientId, func(setA []string, setB []string) []string {
			res := make([]string, 0, len(setA)+len(setB))
			for _, k := range setA {
				res = append(res, k)
			}
			for _, k := range setB {
				res = append(res, k)
			}
			return res
		}(newKeys, clientInfo.StorageKeys))
		if err != nil {
			l.Errorf("SetClientInfoStorageKeys failed: %v", err)
			return err
		}
	}

	// 重新检查 ClientInfo
	clientInfo, err = r.appUsecase.Repo.GetClientInfo(ctx, clientId)
	if err != nil {
		l.Errorf("GetClientInfo failed: %v", err)
		return err
	}
	if clientInfo == nil {
		return kratosErrors.BadRequest("", "get client info failed")
	}

	newKeys = []string{}
	for k := range storageKeyValues {
		occurredKey := false
		for i := range clientInfo.StorageKeys {
			if k == clientInfo.StorageKeys[i] {
				occurredKey = true
			}
		}
		if !occurredKey {
			newKeys = append(newKeys, k)
		}
	}
	if len(newKeys) > 0 {
		l.Errorf("SetUserProfile some storage keys are still invalid after updating client info: %+v", newKeys)
		return kratosErrors.InternalServer("", fmt.Sprintf("some storage keys are still invalid: %+v", newKeys))
	}

	// bson.M: map[string]interface{}
	update := bson.M{}
	for k, v := range storageKeyValues {
		fullKey := clientInfo.Name + "__" + k
		update[fullKey] = v
	}

	userColl := r.userCollection
	_, err = userColl.UpdateOne(ctx, bson.M{"_id": uid}, bson.M{"$set": update})
	if err != nil {
		l.Errorf("SetUserProfile update user error: %v", err)
		return err
	}
	return nil
}

// AllowJTIs writes allowed JTIs to Redis so refresh token validation can be fast.
// Behavior:
// - Stores each provided jti into Redis under key allowed_tokens:<jti> with TTL = refreshTokenLifeSpan.
// - Uses a Redis pipeline for batched writes; ignores empty jti entries.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - jtis: slice of token identifiers to allow.
// Returns:
// - error: non-nil when Redis pipeline Exec fails (other than redis.Nil).
func (r *oauth2Repo) AllowJTIs(ctx context.Context, jtis []string) error {
	// 新的白名单实现：把允许的 jti 写入 Redis，过期时间为 refreshTokenLifeSpan
	if len(jtis) == 0 {
		return nil
	}

	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	l.Debugf("AllowJTIs jtis: %+v", jtis)

	pipe := r.data.redis.Pipeline()
	for _, id := range jtis {
		if id == "" {
			continue
		}
		key := GetRedisKey("allowed_tokens", id)
		pipe.Set(ctx, key, "1", r.refreshTokenLifeSpan)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && !errors.Is(err, redis.Nil) {
		l.Errorf("AllowJTIs pipeline exec error err=%v", err)
		return err
	}
	return nil
}

// RemoveJTIsFormRedis deletes the allowed token keys for the provided JTIs.
// Behavior:
// - Uses a Redis pipeline to DEL allowed_tokens:<jti> for each id, with a short context timeout.
// - Logs failures and returns any pipeline error.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - jtis: slice of token IDs to remove from allowlist.
// Returns:
// - error: non-nil when Redis operations fail.
func (r *oauth2Repo) RemoveJTIsFormRedis(ctx context.Context, jtis []string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	l.Debugf("RemoveJTIsFormRedis jtis: %+v", jtis)

	pipe := r.data.redis.Pipeline()
	for _, id := range jtis {
		if id == "" {
			continue
		}
		key := GetRedisKey("allowed_tokens", id)
		pipe.Del(ctx, key)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// CheckUserPermission determines whether the user has or can be granted permission for the client.
// Behavior:
//   - Loads client metadata and checks existence.
//   - Looks up user_consents for {user_id, client_id}. If not found and the client has
//     Admin == "official" and no optional scopes, auto-creates a consent record (convenience behavior).
//   - If client version mismatches the user's agreed version, returns a Forbidden error.
//
// Parameters:
// - ctx: context for cancellation/timeouts.
// - userId: user identifier.
// - clientId: client identifier.
// Returns:
// - bool: true if permission exists/was created; false otherwise.
// - error: biz.UserPermissionDeniedError when permission denied; kratos errors on invalid client; wrapped DB errors otherwise.
func (r *oauth2Repo) CheckUserPermission(ctx context.Context, userId string, clientId string) (bool, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("CheckUserPermission userId: %s, clientId: %s", userId, clientId)

	clientInfo, err := r.appUsecase.Repo.GetClientInfo(ctx, clientId)
	if err != nil {
		l.Errorf("GetClientInfo failed: %v", err)
		return false, err
	}
	if clientInfo == nil {
		return false, kratosErrors.BadRequest("", "invalid client_id")
	}
	collection := r.userConsentsCollection
	filter := map[string]interface{}{
		"user_id":   userId,
		"client_id": clientId,
	}
	var result struct {
		Scope         []string `bson:"optional_scope"`
		AgreedVersion string   `bson:"agreed_version"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			if clientInfo.Admin != "official" || (clientInfo.OptionalScope != nil && len(clientInfo.OptionalScope) > 0) {
				return false, biz.UserPermissionDeniedError
			}

			record := bson.M{
				"user_id":        userId,
				"client_id":      clientId,
				"token_id":       []string{},
				"granted_at":     time.Now(),
				"agreed_version": clientInfo.Version,
				"optional_scope": []string{},
			}
			_, err = collection.InsertOne(ctx, record)
			if err != nil {
				l.Errorf("InsertOne error: %v", err)
				return false, fmt.Errorf("failed to insert user: %w", err)
			}

		} else {
			l.Errorf("failed to find user consent: %v", err)
			return false, err
		}
	}
	if clientInfo.Version != result.AgreedVersion {
		return false, kratosErrors.Forbidden("", "client version outdated")
	}

	return true, nil
}

// SetClientInfoStorageKeys updates the client's allowed storage keys (currently a placeholder).
// Behavior:
// - Intended to update AppCenter / client metadata and invalidate local cache.
// - Current implementation only deletes local Redis cache and refreshes client info from AppCenter.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - clientId: client identifier.
// - storageKeys: new storage keys to set for the client.
// Returns:
// - error: non-nil if underlying AppCenter call fails.
func (r *oauth2Repo) SetClientInfoStorageKeys(ctx context.Context, clientId string, storageKeys []string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l.Debugf("SetClientInfoStorageKeys clientId: %s, storageKeys: %+v", clientId, storageKeys)
	// TODO : implement the request to set the storageKeys after app center is ready
	key := GetRedisKey("client_info", clientId)
	r.data.redis.Del(ctx, key)
	_, err := r.appUsecase.Repo.GetClientInfo(ctx, clientId)
	return err
}

// 这里的缓存方案需要仔细考虑 一方面 其有效减少了向AppCenter的请求 但另一方面 在一定程度上 其破坏了数据的一致性 让结构不那么干净
// 但是我认为这样的缓存是必要的 TODO 后续应当测试缓存效果

const codeInfoTTL = 5 * time.Minute

// cacheCodeInfo serializes and stores CodeInfo in Redis with a TTL.
// Behavior:
// - Marshals codeInfo to JSON and SETs it to key oauth2_code:<code> with codeInfoTTL.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - code: code string key.
// - codeInfo: metadata to store.
// Returns:
// - error: non-nil on JSON marshal or Redis set error.
func (r *oauth2Repo) cacheCodeInfo(ctx context.Context, code string, codeInfo *biz.CodeInfo) error {
	key := GetRedisKey("oauth2_code", code)

	// 序列化为 JSON
	b, err := json.Marshal(codeInfo)
	if err != nil {
		return err
	}

	// 写入 Redis（设置 TTL）
	return r.data.redis.Set(ctx, key, b, codeInfoTTL).Err()
}

// getCodeInfoFromCache reads and unmarshals CodeInfo from Redis.
// Behavior:
// - GETs oauth2_code:<code>, returns (nil,nil) when key not found (redis.Nil).
// - Unmarshals JSON into biz.CodeInfo and returns it.
// Parameters:
// - ctx: context for cancellation/timeouts.
// - code: code string key.
// Returns:
// - *biz.CodeInfo: pointer to decoded data when present.
// - error: non-nil on Redis errors (other than Nil) or JSON unmarshal failures.
func (r *oauth2Repo) getCodeInfoFromCache(ctx context.Context, code string) (*biz.CodeInfo, error) {
	key := GetRedisKey("oauth2_code", code)

	val, err := r.data.redis.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// 未命中缓存，按你的逻辑可以返回 nil,nil 或去 AppCenter 拉取后再 Cache
			return nil, nil
		}
	}
	var codeInfo biz.CodeInfo
	if err := json.Unmarshal([]byte(val), &codeInfo); err != nil {
		return nil, err
	}
	return &codeInfo, nil
}
