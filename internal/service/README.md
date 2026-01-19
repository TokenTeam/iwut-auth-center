# Service

此目录实现应用的服务（Service）层：对外提供 gRPC API（由 api 定义的 RPC），负责：
- 校验/解析请求与认证信息（主要使用 JWT 工具），
- 调用对应的 usecase/repo（主要是 data 层通过 usecase 暴露的 Repo）完成业务操作，
- 组装 RPC 响应并统一做审计（audit）记录与错误处理。

总体设计与职责
- Service 层不直接操作数据库或缓存；它以业务用例（usecase）和 repo 的抽象为后端。
- 大多数方法的实现都是“验证请求 -> 提取/检查身份 -> 调用 usecase/数据层 -> 构建返回值”，因此 README 中不重复 data 层的实现细节。
- 统一的审计插入逻辑通过 `GetAuditInsertFunc` 与 `util.GetProcesses`（在代码中用于包装成功/失败处理并写审计）完成。
- 常见超时、错误语义与行为受下层 repo 控制；Service 层负责将这些错误转换为 RPC 可返回的格式（例如 gRPC status / OAuth2 规范的 error 字段）。

文件/服务概览

- `service.go`
  - ProviderSet（wire 注入点）：导出 NewAuthService、NewUserService、NewOauth2Service 等构造器供依赖注入使用。
  - `GetAuditInsertFunc(usecase biz.AuditUsecase) func(ctx context.Context, audit util.Audit)`：构造将 util.Audit 转接为 usecase.Repo.InsertAuditForRequest 的函数，作为 `util.GetProcesses` 的审计回调使用。

- `auth.go`（AuthService）
  - 主要职责：登录/注册/刷新令牌/发送验证码等与认证相关的 RPC。核心流程：验证请求 -> 调用 `authUsecase`（和 mailUsecase） -> 签发或刷新 JWT -> 更新用户版本缓存 -> 返回 RPC 结果并写审计。
  - 关键方法：
    - `PasswordLogin`：使用邮箱+密码登录，成功后生成 access/refresh JWT 并更新 user version cache。
    - `GetRegisterMail`：生成验证码，使用 `authUsecase` 做限流/存储，再通过 `mailUsecase` 发送邮件。
    - `GetResetUrlMail`：为密码重置生成带验证码的重置链接并发送邮件。流程：生成安全验证码 -> 调用 `authUsecase.Repo.TryInsertResetPasswordCaptcha` 存储并限流（要求邮箱对应用户必须存在）-> 构建带 email&code 的前端重置 URL -> 通过 `mailUsecase.SendResetPasswordMail` 发送。
    - `ResetPassword`：接收邮箱、验证码与新密码；先通过 `authUsecase.Repo.CheckResetPasswordCaptchaUsable` 校验验证码的可用性，然后调用 `authUsecase.Repo.ResetPassword` 来更新 MongoDB 中的密码（内部会做 sha256 哈希），成功后返回 RPC 成功并写审计。
    - `Register`：验证验证码并委托创建用户（返回 userId）。
    - `RefreshToken`：接受 refresh token（支持从请求体或 Cookie 中获取），校验 token、版本号，然后签发新的 access/refresh token（并做审计）。
  - 注：`GenerateSecure6DigitCode` 是用于邮件验证码的安全随机生成器。

- `user.go`（UserService）
  - 主要职责：用户自管理相关接口（修改密码、删除账号、查询/更新个人资料、管理 consent/profile keys）。
  - 关键方法：
    - `UpdatePassword`：验证并设置新密码，同时通过 `authUsecase` 回写/更新用户版本缓存以失效旧 token。
    - `DeleteAccount`：软删除当前用户并 bump 版本。
    - `GetProfile` / `GetProfileKeys`：读取用户基本信息与可用的 profile keys（由 data 层返回），并转换为 RPC 结构。
    - `UpdateProfile`：接收前端提交的属性（structpb），转为 map 并委托持久化。
    - `UpdateUserConsent`：记录用户对特定客户端的同意/可选权限。
  - 注：Service 层只做参数/身份校验与响应封装，不直接参与数据校验的细节（例如字段大小限制由 data 层 enforce）。

- `oauth2.go`（Oauth2Service）
  - 主要职责：实现 OAuth2 授权码流程与客户端可见的用户信息接口（符合服务的简化 OAuth2 需求），包括：Authorize、GetToken、RevokeAuthorization、GetUserProfile、SetUserStorage。
  - 关键方法与要点：
    - `Authorize`：校验请求参数（scope/response_type/PKCE）并确认用户对客户端有权限后，生成授权码并缓存其元数据，返回带 code 的回调 URL。
    - `GetToken`：使用授权码交换 access/refresh token；包括 PKCE(S256) 验证、client 认证、生成 JTI、签发 JWT、把 JTI 写入 user_consents 并使授权码失效。
    - `RevokeAuthorization`：撤销用户对某客户端的同意（委托 repo 执行原子撤销与清理）。
    - `GetUserProfile`：为已授权的客户端（azp 出自 JWT）返回用户可阅读的属性与 namespaced storage 值（转换为 structpb）。
    - `SetUserStorage`：为客户端写入/更新 namespaced 存储键值（受限于数量/内存限制，由 data 层校验）。
  - 注：Method 内会把 OAuth2 的错误映射为符合规范的 error/description 或 gRPC 状态。

常见调用/执行模式
- 所有 RPC 入口通常按以下步骤执行：
  1. 提取并校验请求参数（以及必要时解析/验证 JWT）。
  2. 使用 usecase/Repo 执行业务逻辑（data 层实现具体的持久化、缓存与一致性保证）。
  3. 根据结果构建 RPC 响应；对错误进行包装以便上层客户端能明确错误类型（例如 400/401/403/500）。
  4. 通过 `util.GetProcesses` 与 `GetAuditInsertFunc` 统一插入审计记录（成功或失败）。

错误处理与审计
- 服务方法通常使用 `util.GetProcesses` 帮助器来统一处理成功/失败流程与审计回调。审计内容通过 `GetAuditInsertFunc` 转接到 `biz.AuditUsecase`。
- Service 层会把底层 repo 返回的业务错误（在 `internal/biz` 中定义的一些语义错误）沿链返回或转为 RPC 友好格式。

运行时注意事项与建议
- 超时与鲁棒性：data 层在大多数方法中会使用 5s/10s 的短超时，Service 层不应随意延长这些超时，除非业务确有需要并与下层协同。
- 审计与丢失：Audit 采用异步队列写入（data 层），在高负载下可能丢弃审计条目（这是设计权衡）；若需要 100% 保证请考虑同步或持久化缓冲。
- 缓存一致性：OAuth2 的 client 信息和 token 白名单在 Redis 中有缓存写回/失效机制；跨实例一致性需要在部署时评估（例如 TTL、主动失效策略）。
