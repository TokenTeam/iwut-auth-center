# Data

此目录实现了数据访问层（MongoDB、Redis、MySQL via GORM）的仓库（repo）和资源初始化/清理逻辑。

下面按文件/组件对 package `internal/data` 的主要职责、导出类型与重要函数做摘要（中文）：

概览
- 提供数据库/缓存客户端的初始化与关闭（NewData 返回 cleanup 函数）。
- 提供若干 repo 的具体实现：Audit、Auth、User、Oauth2、App（AppRepo 在代码中为 NewAppRepo）。
- 大部分方法对外返回业务层约定的错误（见 internal/biz），并在内部对 Mongo/Redis 操作使用短超时以避免阻塞调用者。

生命周期与初始化（data.go）
- NewData(c *conf.Data, logger log.Logger) (*Data, func(), error)
  - 初始化顺序：MongoDB -> Redis -> MySQL（GORM）。
  - 若中途失败会关闭已成功打开的客户端并返回错误。
  - 返回的 cleanup() 会并发关闭 mongo/redis/mysql 并记录错误。
- ensureUserEmailUniqueIndex(ctx, col *mongo.Collection)
  - 为 `user.email` 创建唯一索引（如果需要请在迁移阶段管理）。
- initMongo / initRedis / initMySQL
  - 各自负责连接与连通性检测（ping），均有超时保护。
- RedisPrefixKey 与 GetRedisKey(keys ...string) string
  - 从配置读取 redis 前缀（若未配置使用默认 `AuthCenter:`），并用于构建 namespaced key。

并发、超时、日志与错误处理（总述）
- 大多数对外方法在内部使用 5s 或 10s 的 context 超时以避免长时间阻塞。
- 写操作在发生内部错误时会记录日志并返回包装错误，部分情况下会返回 biz 包定义的语义错误（例如 UserNotFoundError 等）。
- 方法对 Redis 的缺失键（redis.Nil）通常被视为“未命中”并以业务语义处理（例如验证码不可用、code 过期等）。

Audit（audit.go）
- NewAuditRepo(data *Data, logger log.Logger) (biz.AuditRepo, func(), error)
  - 创建一个带缓冲通道的异步写入队列（默认 channel buffer 512，workers 2），返回 repo 实例和 cleanup 函数。
  - cleanup/Close 会优雅地关闭通道并等待 worker 处理完队列。
- Audit 结构体
  - GORM 模型，含 BeforeCreate hook 自动填充 UUID。
- InsertAuditForRequest(...)
  - 非阻塞入队（若队列已满则丢弃并记录 Warn），保证 API 低延迟。
- auditWorker
  - 后台 goroutine 消费队列并写入 DB，每次写入使用短超时并带简单重试与回退日志。

Auth（auth.go）
- NewAuthRepo(...)
  - 绑定 user collection 并返回 authRepo 实现。
- CheckPasswordWithEmailAndGetUserIdAndVersion(ctx, email, password)
  - 使用 sha256 哈希密码并在 Mongo 查询，处理软删除恢复（30 天内可恢复）。
  - 返回 userId（hex）与版本号，未找到返回 biz.UserNotFoundError。
- TryInsertRegisterCaptcha(ctx, email, captcha, ttl)
  - 在 Redis 的有序集合（register_captcha:<email>）中写入验证码并做限流（最近一条间隔至少 1 分钟）；若 email 已注册返回 biz.UserAlreadyExistsError。
- CheckCaptchaUsable(ctx, email, code, ttl)
  - 清理过期条目并通过 ZRank 检查验证码是否存在，redis.Nil 映射为 biz.CaptchaNotUsableError。
- TryInsertResetPasswordCaptcha(ctx, email, captcha, ttl)
  - 为重置密码生成/存储验证码并做限流：先在 MongoDB 的 `user` 集合中检查 `email` 是否存在，若不存在返回 biz.UserNotFoundError；再在 Redis 有序集合（reset_password_captcha:<email>）中写入验证码并限制最短请求间隔为 1 分钟（间隔过短返回 biz.AskingCaptchaTooFrequentlyError）；插入后会清理过期条目并设置键的 TTL。
- CheckResetPasswordCaptchaUsable(ctx, email, code, ttl)
  - 与注册验证码的检查类似：先清理过期条目，然后通过 ZRank 检查 code 是否存在；不存在返回 biz.CaptchaNotUsableError，其他 Redis 错误上抛。
- ResetPassword(ctx, email, newPassword)
  - 对新密码做 sha256 哈希并在 MongoDB 中按 `email` 更新用户的 `password` 字段与 `updated_at`；若没有匹配的用户返回 biz.UserNotFoundError。
- RegisterUser(ctx, email, password)
  - Hash 密码后通过 Upsert 插入用户（$setOnInsert），若已存在返回 biz.UserAlreadyExistsError；返回插入的 id。</n
- AddOrUpdateUserVersion / GetUserVersion
  - 将用户版本缓存在 Redis（user_version:<userId>），GetUserVersion 在缓存缺失情况下回退到 Mongo 并尝试回填缓存；对不存在或已删除用户返回对应 biz 错误。

User（user.go）
- NewUserRepo(...)
  - 绑定 user 与 user_consents collection，同时读取官方信息内存限制配置。
- UpdateUserPassword(ctx, userId, oldPassword, newPassword)
  - 验证旧密码并原子更新为新密码，同时更新时间并 bump Version（以使旧 token 失效）。
- DeleteUserAccount(ctx, userId)
  - 软删除：设置 deleted_at/updated_at 并 bump Version。
- GetUserProfileById(ctx, userId) (*biz.UserProfile, error)
  - 返回用户的基本信息以及以 `official__` 前缀存储的官方字段（去掉前缀后返回 map）；使用 aggregate pipeline 整理字段。
- UpdateUserProfile(ctx, userId, attrs map[string]string)
  - 将 attrs 以 `official__<key>` 写入用户文档，检查总内存限制（officialInfoMemoryLimitation），检测用户是否删除。
- GetUserProfileKeysById(ctx, userId)
  - 返回基础键列表与额外的 `official__` 键（去前缀后）。
- UpdateUserConsent(ctx, userId, clientId, clientVersion, optionalScopes)
  - 验证 client 存在且版本匹配，校验 optionalScopes 属于 client 可选范围后 upsert 到 `user_consents`。

OAuth2（oauth2.go）
- NewOauth2Repo(...)
  - 绑定 user 与 user_consents collection，读取 refresh token 生命周期与 oauth2 内存限制。
- CheckGetCodeRequest(ctx, codeInfo *biz.CodeInfo) (bool, error)
  - 验证 scope 与 response_type、用户对客户端权限、redirect_uri 是否匹配。
- SetCodeInfo / GetCodeInfo / EraseCodeInfo
  - 将授权 code 的元信息序列化为 JSON 缓存到 Redis（短 TTL，codeInfoTTL = 5 分钟）；GetCodeInfo 在未命中时返回 (nil, nil)；EraseCodeInfo 删除 Redis 键。
- InsertJTIToUserConsents / RevokeUserConsent / CheckJTIAllowed / AllowJTIs / RemoveJTIsFormRedis
  - JTIs 管理：在 user_consents 文档上维护 token_id 列表（最多保留 5 个），并在 Redis 中写入允许的 jti（allowed_tokens:<jti>）以便快速验证刷新 token。Revoke 和 移除操作会从 Redis 删除对应键。
  - CheckJTIAllowed 首先查 Redis，未命中则回退到 Mongo 并尝试写回 Redis（写回失败不影响返回结果，只记录日志）。
- GetUserProfile(ctx, userId, clientId, scopes, storageKeys)
  - 返回客户端可见的用户信息：
    - 计算可读 scopes（client basic scope 与用户已授予的 optional scope 的交集），拒绝读取敏感 scope（如 password）。
    - 根据 readable scopes 投影 user collection 字段并转换类型（util.ConvertBSONValueToGOType）。
    - storageKeys 会被 namespaced 为 <clientName>__<key> 并返回值或 nil。
- SetUserProfile(ctx, userId, clientId, storageKeyValues)
  - 为客户端设置/更新 namespaced 存储键值对，检查键数量限制（<=20）与内存限制（oauth2InfoMemoryLimitation）。
  - 如果出现新 key，会尝试通过 SetClientInfoStorageKeys 更新客户端信息（当前实现仅清理本地缓存并重新拉取）。
- CheckUserPermission(ctx, userId, clientId)
  - 校验客户端是否存在并检查 user_consents 记录；当 client.Admin == "official" 且无 optional scope 时，会自动创建一个空的 consent 记录以便方便服务间授权。
- SetClientInfoStorageKeys(ctx, clientId, storageKeys)
  - 占位实现：当前仅删除本地 Redis 缓存并触发从 AppCenter 重新拉取 client info；TODO：后续与 AppCenter 集成以更新客户端元数据。

注意事项与建议
- 容错：Audit 写入采用异步队列并在队列满时丢弃以保证请求路径低延迟；这意味着 audit 丢失是有可能的，针对关键审计可以改为同步或持久化缓冲。
- 缓存一致性：Oauth2 对 client 信息有本地缓存（Redis），SetClientInfoStorageKeys 当前只清空缓存并重新拉取。分布式一致性要求需在设计时仔细评估。
- 错误语义：很多方法会返回 internal/biz 中定义的语义错误（例如 UserNotFoundError, UserHasBeenDeletedError, AskingCaptchaTooFrequentlyError 等），上层应使用这些错误进行流程控制。

