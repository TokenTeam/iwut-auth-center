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
	userUsecase                *biz.UserUsecase
	userCollection             *mongo.Collection
	userConsentsCollection     *mongo.Collection
	refreshTokenLifeSpan       time.Duration
	oauth2InfoMemoryLimitation int64
}

// NewOauth2Repo constructs an oauth2 repository backed by MongoDB and Redis.
// It binds the `user` and `user_consents` collections and reads relevant
// configuration (refresh token TTL and per-user storage memory limits).
// It does not mutate DB schema or create indexes.
func NewOauth2Repo(data *Data, c *conf.Data, jwtConf *conf.Jwt, appUsecase *biz.AppUsecase, userUsecase *biz.UserUsecase, logger log.Logger) biz.Oauth2Repo {
	dbName := c.GetMongodb().GetDatabase()
	usersCollection := data.mongo.Database(dbName).Collection("user")
	userConsentsCollection := data.mongo.Database(dbName).Collection("user_consents")

	return &oauth2Repo{
		data:                       data,
		log:                        log.NewHelper(logger),
		appUsecase:                 appUsecase,
		userUsecase:                userUsecase,
		userCollection:             usersCollection,
		userConsentsCollection:     userConsentsCollection,
		refreshTokenLifeSpan:       time.Duration(jwtConf.GetRefreshTokenLifeSpan()) * time.Second,
		oauth2InfoMemoryLimitation: c.GetMongodb().GetLimitations().GetUser().GetOauth2MemLimit(),
	}
}

// CheckGetCodeRequest
// 简介：校验授权码请求的基本合法性与权限。
// 行为说明：
// - 验证 codeInfo.Scope 与 codeInfo.ResponseType 是否为支持的值。
// - 调用 CheckUserPermission 验证用户对客户端的访问权限。
// - 通过 appUsecase 获取客户端注册的 redirect_uri 列表，确保请求中的 redirect_uri 匹配其中之一。
// 参数：
// - ctx: 上下文，用于超时和取消控制。
// - codeInfo: *biz.CodeInfo，包含 userId、clientId、redirectUri、scope、responseType 等信息。
// 返回值：
// - bool: 请求合法且被允许时返回 true，否则返回 false。
// - error: 发生错误或请求不合法时返回相应的 kratos 错误或封装后的内部错误。
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

	if ok, err := r.CheckUserPermission(ctx, userId, codeInfo.ClientId, codeInfo.InternalVersion); !ok {
		return false, err
	}
	//clientInfo, err := r.appUsecase.Repo.GetApplicationInfo(ctx, codeInfo.ClientId)

	userApplicationVersionInfo, err := r.appUsecase.Repo.GetUserApplicationVersionInfo(ctx, codeInfo.ClientId, codeInfo.UserId, codeInfo.InternalVersion)
	if err != nil {
		l.Errorf("GetApplicationInfo failed: %v", err)
		return false, err
	}
	if userApplicationVersionInfo == nil {
		return false, kratosErrors.BadRequest("", "invalid client_id or user_id")
	}
	if func(redirectUri []string) bool {
		for _, url := range redirectUri {
			if codeInfo.RedirectUri == url {
				return true
			}
		}
		return false
	}(userApplicationVersionInfo.RedirectUri) {
		return true, nil
	}

	return false, kratosErrors.BadRequest("", "redirect_uri mismatch")
}

// SetCodeInfo
// 简介：将授权码相关的元数据序列化并写入 Redis（短期缓存）。
// 行为说明：
// - 将传入的 CodeInfo 序列化为 JSON。
// - 使用带 TTL 的 Redis SET 操作写入缓存以便后续校验/读取。
// 参数：
// - ctx: 上下文，用于超时和取消控制。
// - code: 授权码字符串，作为 Redis key 的一部分。
// - codeInfo: *biz.CodeInfo，需被序列化并缓存的值。
// 返回值：
// - error: 当序列化或 Redis 操作失败时返回非 nil 错误，成功返回 nil。
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

// GetCodeInfo
// 简介：从 Redis 读取并反序列化授权码相关的元数据。
// 行为说明：
// - 从 Redis GET 指定的 key，若未命中返回 (nil, nil)。
// - 将读取到的 JSON 反序列化为 biz.CodeInfo 并返回。
// 参数：
// - ctx: 上下文，用于超时和取消控制。
// - code: 授权码字符串，作为 Redis key 的一部分。
// 返回值：
// - *biz.CodeInfo: 成功读取并反序列化时返回指针，未命中时返回 nil。
// - error: Redis 或反序列化出错时返回相应错误。
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

// EraseCodeInfo
// 简介：从 Redis 删除指定的授权码缓存，使该授权码失效。
// 行为说明：
// - 调用 Redis DEL 删除对应的 oauth2_code:<code> 键。
// 参数：
// - ctx: 上下文，用于超时和取消控制。
// - code: 授权码字符串，作为 Redis key 的一部分。
// 返回值：
// - error: Redis 删除操作失败时返回错误，成功返回 nil。
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

// InsertJTIToUserConsents
// 简介：向 user_consents 文档追加新的 JTI 并在 Redis 上写入允许列表，同时控制保留的 JTI 列表长度。
// 行为说明：
// - 从 user_consents 中读取当前 token_id 列表并在末尾追加新的 jti。
// - 将该 jti 写入 Redis 的允许列表以便快速校验（AllowJTIs）。
// - 若追加后列表长度超过上限（5），截断保留最新 5 个并将被截断的旧 JTI 移出 Redis（RemoveJTIsFormRedis）。
// - 将更新后的 token_id 列表写回 MongoDB（UpdateOne）。
// 参数：
// - ctx: 上下文，用于超时和取消控制。
// - userId: 用户标识（在 user_consents 中作为 user_id 存储）。
// - clientId: 客户端标识（在 user_consents 中作为 client_id 存储）。
// - jti: 要追加的 token 标识符。
// 返回值：
// - error: 当找不到对应的 user_consents、Mongo/Redis 操作失败或其他内部错误时返回非 nil 错误，成功返回 nil。
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

// RevokeUserConsent
// 简介：原子性地撤销用户对某客户端的同意，清空 token_id 并从 Redis 中移除对应允许的 JTI。
// 行为说明：
// - 使用 FindOneAndUpdate 原子地读取并将 token_id 字段置为空，同时获取更新前的值。
// - 若找到旧的 token_id 列表，则调用 RemoveJTIsFormRedis 将这些 JTI 从 Redis 允许列表中删除。
// 参数：
// - ctx: 上下文，用于超时和取消控制。
// - userId: 用户标识（在 user_consents 中作为 user_id 存储）。
// - clientId: 客户端标识（在 user_consents 中作为 client_id 存储）。
// 返回值：
// - error: 找不到 user_consents 时返回 NotFound；Mongo/Redis 等操作出错时返回相应错误，成功返回 nil。
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

// GetUserOfficialProfile 返回客户端可读取的“官方”用户资料字段（非 per-client storage）。
//
// 行为说明：
// - 加载 client 的用户/版本信息（通过 appUsecase.Repo.GetUserApplicationVersionInfo），并校验 client 与用户的关联性。
// - 从 user_consents 中读取该 user 对该 client 的同意信息（包括 optional_scope 与 agreed_version）。
// - 计算可读取的官方 scope：client 的 BasicScope 与用户同意的 OptionalScope 的并集（只保留以 "read__" 前缀定义的 scope 并去掉前缀）。
// - 验证请求的 scopes 都在可读取集合内；若请求 scope 未被授予，则返回 Forbidden（权限不足）。
// - 禁止读取敏感字段（例如 "password"）；若包含则返回 Forbidden。
// - 将 userId 转为 MongoDB ObjectID，并使用 Aggregation（$match + $project）只投影所需的字段以减少数据传输。
// - 使用 util.ConvertBSONValueToGOType 将 BSON 值转换为 Go 原生类型；若转换失败返回 InternalServer 错误。
//
// 参数：
// - ctx: 上下文，用于超时/取消。
// - userId: 用户的 MongoDB ObjectID 的 hex 字符串。
// - clientId: 客户端标识。
// - internalVersion: 请求的客户端内部版本（用于与用户同意的版本比对）。
// - scopes: 请求读取的官方字段名列表（不带 read__ 前缀）。
//
// 返回值：
// - map[string]any: key 为请求的 scope 名（原始名），value 为对应字段的值（当字段不存在或为 null 时为 nil）。
// - error: 当发生以下情况返回非 nil：
//   - client/user/consent 信息缺失或无效 -> NotFound / BadRequest（视具体情形）
//   - 请求的 scope 未被授予或 client 版本过旧 -> Forbidden
//   - Mongo/Redis 等内部错误或 BSON 到 Go 类型转换失败 -> Wrapped error
//
// 注意与实现要点：
// - 函数依赖 appUsecase 与 userConsentsCollection 来校验权限与同意版本。
// - 投影字段使用了 mongo.Aggregate，减少从 DB 拉取的字段。
// - 该函数只返回“官方”字段（由 client 的 BasicScope/OptionalScope 控制），不处理 per-client 的 storage key。
func (r *oauth2Repo) GetUserOfficialProfile(ctx context.Context, userId string, clientId string, internalVersion int32, scopes []string) (map[string]any, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("GetUserOfficialProfile userId: %s, clientId: %s, internalVersion: %d", userId, clientId, internalVersion)

	userApplicationVersionInfo, err := r.appUsecase.Repo.GetUserApplicationVersionInfo(ctx, clientId, userId, internalVersion)
	if err != nil {
		l.Errorf("GetUserOfficialProfile GetUserApplicationVersionInfo failed: %v", err)
		return nil, err
	}
	if userApplicationVersionInfo == nil {
		// 该情况实际不应该出现 如果返回nil 那么请求应该会返回一个错误
		return nil, kratosErrors.NotFound("404", "client version or user not found")
	}
	collection := r.userConsentsCollection
	filter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
		"type":      userApplicationVersionInfo.Type,
	}
	var result struct {
		OptionalScope []string `bson:"optional_scope"`
		AgreedVersion int32    `bson:"agreed_version"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		l.Errorf("GetUserOfficialProfile FindOne error: %v", err)
		return nil, err
	}
	if userApplicationVersionInfo.InternalVersion != result.AgreedVersion {
		// TODO 此处应有自动升级策略  检测相关Scope是否是包含关系 若是 则用户同意版本 = max(用户同意版本，请求版本) 否则 报错
		l.Errorf("GetUserOfficialProfile AgreedVersion error: %v", result.AgreedVersion)
		return nil, kratosErrors.Forbidden("", "client version outdated")
	}

	// 在此处计算可读 scopes：先取并集 clientInfo.BasicScope（程序必要） U result.OptionalScope
	// readableScope 语义 所有可以被读取的 官方scope集合
	readableScope := make(map[string]struct{})
	for _, s := range userApplicationVersionInfo.BasicScope {
		if strings.HasPrefix(s, "read__") {
			readableScope[s[6:]] = struct{}{}
		}
	}
	for _, s := range result.OptionalScope {
		if strings.HasPrefix(s, "read__") {
			readableScope[s[6:]] = struct{}{}
		}
	}
	// 做交集 — 遍历 scopes（请求的数据键集合）并检查是否在 readableScope 中
	var readScopes []string
	seen := make(map[string]struct{})
	for _, s := range scopes {
		if _, ok := readableScope[s]; ok {
			// 存在 去重
			if _, dup := seen[s]; !dup {
				readScopes = append(readScopes, s)
				seen[s] = struct{}{}
			}
		} else {
			// 不存在 报错
			l.Errorf("GetUserProfile scope '%s' not granted", s)
			return nil, kratosErrors.Forbidden("", fmt.Sprintf("permission denied for scope '%s'", s))
		}
	}

	// 关键键检查 理论不可能
	if _, ok := seen["password"]; ok {
		l.Errorf("GetUserProfile try to read sensitive scope 'password'")
		return nil, kratosErrors.Forbidden("", "permission denied for scope 'password'")
	}

	uid, err := bson.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return nil, fmt.Errorf("invalid userId format: %s", userId)
	}

	proj := bson.D{}
	for _, s := range readScopes {
		proj = append(proj, bson.E{Key: s, Value: 1})
	}
	pipeline := mongo.Pipeline{
		{{"$match", bson.D{{"_id", uid}}}},
		{{"$project", proj}},
	}

	cur, err := r.userCollection.Aggregate(ctx, pipeline)
	if err != nil {
		l.Errorf("GetUserOfficialProfile aggregate err: %v", err)
		return nil, err
	}
	defer func() { _ = cur.Close(ctx) }()

	if !cur.Next(ctx) {
		if err := cur.Err(); err != nil {
			l.Errorf("GetUserOfficialProfile cursor error: %v", err)
			return nil, err
		}
		// 用户不存在
		return nil, biz.UserNotFoundError
	}
	var doc bson.M
	if err := cur.Decode(&doc); err != nil {
		l.Errorf("GetUserOfficialProfile decode user doc error: %v", err)
		return nil, err
	}

	officialScope := map[string]any{}
	for _, k := range scopes {
		// check if k in doc
		if val, ok := doc[k]; ok {
			conv, err := util.ConvertBSONValueToGOType(val)
			if err != nil {
				l.Errorf("GetUserOfficialProfile scope '%s' has unsupported type: %v", k, err)
				return nil, kratosErrors.InternalServer("", fmt.Sprintf("scope '%s' has unsupported type", k))
			}
			officialScope[k] = conv
		} else {
			officialScope[k] = nil
		}
	}
	return officialScope, nil
}

// GetUserProfile
// 简介：读取某用户针对某客户端的 per-client 存储键（storage keys）。
// 行为说明：
// - 验证客户端存在并且用户已对该客户端给出同意（通过 user_consents）。
// - 将要读取的字段按 `<applicationId>.<key>` 的形式投影查询用户集合以减少数据传输量。
// - 将查询结果中的 BSON 值转换为 Go 原生类型，并以 map[string]*string 返回（不存在或 null 返回 nil）。
// - 不处理“官方”scope 字段，仅针对 per-client 的存储字段。
// 参数：
// - ctx: 上下文，用于超时/取消。
// - userId: 用户的 MongoDB ObjectID hex 字符串。
// - clientId: 客户端标识（用于定位 applicationId 命名空间）。
// - storageKeys: 请求读取的存储键名列表（不包含 applicationId 前缀）。
// 返回值：
// - map[string]*string: key 为原始 storage key，value 为该字段的字符串指针（不存在或为 null 时为 nil）。
// - error: 找不到用户/未授权/DB 或转换错误时返回相应错误。
func (r *oauth2Repo) GetUserProfile(ctx context.Context, userId string, clientId string, storageKeys []string) (map[string]*string, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("GetUserProfile userId: %s, clientId: %s", userId, clientId)

	applicationInfo, err := r.appUsecase.Repo.GetApplicationInfo(ctx, clientId)
	if err != nil {
		l.Errorf("GetApplicationInfo failed: %v", err)
		return nil, err
	}
	if applicationInfo == nil {
		return nil, kratosErrors.BadRequest("", "get application info failed")
	}

	filter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
	}

	err = r.userConsentsCollection.FindOne(ctx, filter, options.FindOne().SetProjection(bson.M{"_id": 1})).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		l.Errorf("GetUserProfile user consent not found for userId: %s, clientId: %s", userId, clientId)
		return nil, kratosErrors.NotFound("404", "user consent not found")
	} else if err != nil {
		l.Errorf("GetUserProfile FindOne error: %v", err)
		return nil, err
	}

	// convert userId to ObjectID for querying user collection
	uid, err := bson.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return nil, fmt.Errorf("invalid userId format: %s", userId)
	}

	// --- 新版：直接从 userCollection 中按 readableScopes 投影字段 ---
	// 始终包含 _id 以便返回 UserId
	proj := bson.D{}
	for _, s := range storageKeys {
		proj = append(proj, bson.E{Key: applicationInfo.Id + "." + s, Value: 1})
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

	storageKeyValue := map[string]*string{}
	getter := func(key string, doc map[string]any) (*string, error) {
		keys := strings.Split(key, ".")
		var errorKey string
		if len(keys) > 0 {
			errorKey = keys[len(keys)-1]
		}
		errorKey = key
		for i, k := range keys {
			if val, ok := doc[k]; ok {
				conv, err := util.ConvertBSONValueToGOType(val)
				if err != nil {
					l.Errorf("GetUserProfile storage key '%s' has unsupported type: %v", errorKey, err)
					return nil, kratosErrors.InternalServer("", fmt.Sprintf("storage key '%s' is invalid", k))
				}
				if conv == nil {
					return nil, nil
				} else if s, ok := conv.(map[string]any); ok {
					if i < len(keys)-1 {
						doc = s
					} else {
						return nil, nil
					}
				} else if s, ok := conv.(string); ok {
					if i == len(keys)-1 {
						return &s, nil
					}
				} else {
					l.Errorf("GetUserProfile storage key '%s' is invalid type: %T", errorKey, conv)
					return nil, kratosErrors.InternalServer("", fmt.Sprintf("storage key '%s' is invalid", k))
				}
			}
		}
		return nil, nil
	}
	for _, k := range storageKeys {
		fullKey := applicationInfo.Id + "." + k
		val, err := getter(fullKey, doc)
		if err != nil {
			return nil, err
		}
		storageKeyValue[k] = val
	}
	return storageKeyValue, nil
}

// SetUserProfile
// 简介：为某用户在指定客户端下批量设置或更新 per-client 存储键值对。
// 行为说明：
// - 校验输入限制（单次键数量上限、键名合法性、总内存限制等）。
// - 验证客户端存在并且用户已对该客户端给出同意（user_consents）。
// - 读取当前 per-client 存储映射，合并入新值，重新计算限制并写回（使用 $set 与点位符字段名 `<applicationId>.<key>`）。
// - 若数据库中存在非法键，会尝试清理（$unset）。
// 参数：
// - ctx: 上下文。
// - userId: 用户的 MongoDB ObjectID hex 字符串。
// - clientId: 客户端标识。
// - storageKeyValues: 要写入或更新的键->值映射（键为纯 key，不含 applicationId 前缀）。
// 返回值：
// - error: 参数非法、超出配额、未授权或 DB 写入出错时返回对应错误，成功返回 nil。
func (r *oauth2Repo) SetUserProfile(ctx context.Context, userId string, clientId string, storageKeyValues map[string]string) error {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	uid, err := bson.ObjectIDFromHex(userId)
	if err != nil {
		l.Errorf("invalid userId format: %s", userId)
		return fmt.Errorf("invalid userId format: %s", userId)
	}

	if len(storageKeyValues) > 1000 {
		l.Errorf("too many storage keys to set: %d", len(storageKeyValues))
		return kratosErrors.BadRequest("", "too many storage keys to set")
	}

	var totalLength int64
	totalLength = 0
	for k, v := range storageKeyValues {
		if k == "" || strings.ContainsAny(k, ".$") || strings.IndexByte(k, 0) != -1 {
			l.Errorf("invalid storage key: '%s': must be non-empty and cannot contain '.', '$', or null byte", k)
			return kratosErrors.BadRequest("", fmt.Sprintf("invalid storage key '%s'", k))
		}
		totalLength += int64(len(k) + len(v))
	}

	if totalLength > r.oauth2InfoMemoryLimitation {
		l.Errorf("oauth info memory limitation exceeded: %d > %d", totalLength, r.oauth2InfoMemoryLimitation)
		return biz.OAuth2InfoMemoryLimitationExceededError
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	l.Debugf("SetUserProfile userId: %s clientId: %s", userId, clientId)

	applicationInfo, err := r.appUsecase.Repo.GetApplicationInfo(ctx, clientId)
	if err != nil {
		l.Errorf("GetApplicationInfo failed: %v", err)
		return err
	}
	if applicationInfo == nil {
		return kratosErrors.BadRequest("", "get client info failed")
	}

	filter := bson.M{
		"user_id":   userId,
		"client_id": clientId,
	}

	err = r.userConsentsCollection.FindOne(ctx, filter, options.FindOne().SetProjection(bson.M{"_id": 1})).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		l.Errorf("SetUserProfile user consent not found for userId: %s, clientId: %s", userId, clientId)
		return kratosErrors.NotFound("404", "user consent not found")
	} else if err != nil {
		l.Errorf("SetUserProfile FindOne error: %v", err)
		return err
	}

	filter = bson.M{
		"_id": uid,
	}

	var doc bson.M
	err = r.userCollection.FindOne(ctx, filter, options.FindOne().SetProjection(bson.M{applicationInfo.Id: 1})).Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			l.Errorf("SetUserProfile user not found for userId: %s", userId)
			return biz.UserNotFoundError
		}
		l.Errorf("SetUserProfile FindOne error: %v", err)
		return err
	}
	existedKeyValue, illegalKeys, err := util.BsonMToStringMap(doc)
	if illegalKeys != nil {
		l.Warnf("SetUserProfile illegalKeys: %v", illegalKeys)
		delKeys := make(map[string]string)
		for k := range illegalKeys {
			delKeys[applicationInfo.Id+"."+k] = ""
		}
		_, err = r.userCollection.UpdateOne(ctx, filter, bson.M{"$unset": delKeys})
		if err != nil {
			l.Errorf("SetUserProfile cleanup illegal keys error: %v", err)
		}
	}
	for k, v := range storageKeyValues {
		existedKeyValue[k] = v
	}

	if len(existedKeyValue) > 1000 {
		l.Errorf("too many storage keys to set: %d", len(existedKeyValue))
		return kratosErrors.BadRequest("", "too many storage keys to set")
	}

	totalLength = 0
	for k, v := range existedKeyValue {
		totalLength += int64(len(k) + len(v))
	}

	if totalLength > r.oauth2InfoMemoryLimitation {
		l.Errorf("oauth info memory limitation exceeded: %d > %d", totalLength, r.oauth2InfoMemoryLimitation)
		return biz.OAuth2InfoMemoryLimitationExceededError
	}

	update := bson.M{}
	for k, v := range existedKeyValue {
		fullKey := applicationInfo.Id + "." + k
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

// AllowJTIs
// 简介：将给定的 JTI 写入 Redis 允许列表以便快速校验刷新令牌。
// 行为说明：
// - 使用 Redis pipeline 批量写入每个非空 jti 到 key `allowed_tokens:<jti>`，并设置过期时间为配置的 refreshTokenLifeSpan。
// - 跳过空字符串。
// 参数：
// - ctx: 上下文。
// - jtis: JTI 字符串切片。
// 返回值：
// - error: Redis 操作失败时返回错误，成功返回 nil。
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

// RemoveJTIsFormRedis
// 简介：从 Redis 中删除给定的一组 JTI 对应的允许键，撤销允许。
// 行为说明：
// - 使用 Redis pipeline 批量执行 DEL 操作删除每个 allowed_tokens:<jti> 键。
// - 跳过空字符串。
// 参数：
// - ctx: 上下文。
// - jtis: 要删除的 JTI 列表。
// 返回值：
// - error: Redis 删除失败时返回错误，成功返回 nil。
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

// CheckUserPermission
// 简介：检查并确保用户对指定客户端具有操作权限（或在条件下自动创建同意记录）。
// 行为说明：
// - 通过 appUsecase.Repo.GetUserApplicationVersionInfo 加载客户端与版本信息。
// - 在 user_consents 中查找 (user_id, client_id) 的同意记录：
//   - 若存在则检查 agreed_version 是否与客户端 internalVersion 匹配，否则返回 Forbidden。
//   - 若不存在且客户端有 optional scopes：若该客户端不是官方（非 "official." 前缀），则拒绝；否则自动创建空的同意记录（调用 userUsecase.Repo.UpdateUserConsent）。
//
// 参数：
// - ctx: 上下文。
// - userId: 用户标识。
// - clientId: 客户端标识。
// - internalVersion: 客户端的内部版本号，用于与用户已同意的版本比对。
// 返回值：
// - bool: 若用户被允许则返回 true（包含自动创建成功的情形）。
// - error: 无权限、无效客户端或 DB 访问错误时返回相应错误。
func (r *oauth2Repo) CheckUserPermission(ctx context.Context, userId string, clientId string, internalVersion int32) (bool, error) {
	l := log.NewHelper(log.WithContext(ctx, r.log.Logger()))

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	l.Debugf("CheckUserPermission userId: %s, clientId: %s", userId, clientId)

	applicationInfo, err := r.appUsecase.Repo.GetUserApplicationVersionInfo(ctx, clientId, userId, internalVersion)
	if err != nil {
		l.Errorf("GetApplicationInfo failed: %v", err)
		return false, err
	}
	if applicationInfo == nil {
		return false, kratosErrors.BadRequest("", "invalid client_id")
	}
	collection := r.userConsentsCollection
	filter := map[string]interface{}{
		"user_id":   userId,
		"client_id": clientId,
	}
	var result struct {
		Scope         []string `bson:"optional_scope"`
		AgreedVersion int32    `bson:"agreed_version"`
	}
	err = collection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			if applicationInfo.OptionalScope != nil && len(applicationInfo.OptionalScope) > 0 {
				// 这里 applicationInfo.Id 是否为官方的判断其实有点惊险(?) 但我感觉没问题
				if !strings.HasPrefix(applicationInfo.Id, "official.") {
					return false, biz.UserPermissionDeniedError
				}
			}
			err = r.userUsecase.Repo.UpdateUserConsent(ctx, userId, clientId, applicationInfo.InternalVersion, []string{})
			if err != nil {
				l.Errorf("auto-create user consent error: %v", err)
				return false, err
			}
		} else {
			l.Errorf("failed to find user consent: %v", err)
			return false, err
		}
	} else if applicationInfo.InternalVersion != result.AgreedVersion {
		// TODO 此处应有自动升级策略  检测相关Scope是否是包含关系 若是 则用户同意版本 = max(用户同意版本，请求版本) 否则 报错
		return false, kratosErrors.Forbidden("", "client version outdated")
	}
	return true, nil
}

// 这里的缓存方案需要仔细考虑 一方面 其有效减少了向AppCenter的请求 但另一方面 在一定程度上 其破坏了数据的一致性 让结构不那么干净
// 但是我认为这样的缓存是必要 TODO 后续应当测试缓存效果

const codeInfoTTL = 5 * time.Minute

// cacheCodeInfo serializes and stores CodeInfo in Redis with a TTL.
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
