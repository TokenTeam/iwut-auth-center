# 吾理经纬 用户中心 (iwut-auth-center)

负责用户数据记录、认证和 OAuth2 授权的微服务。

## 技术栈

- **语言**：Go 1.24
- **框架**：[Kratos v2](https://go-kratos.dev/)（HTTP + gRPC 双协议）
- **依赖注入**：Google Wire
- **数据库**：MongoDB（go.mongodb.org/mongo-driver/v2）
- **缓存**：Redis（go-redis/v8）
- **认证**：JWT RS256（golang-jwt/v5）
- **可观测性**：OpenTelemetry（OTLP gRPC 导出 trace）、Zap 日志
- **API 定义**：Protocol Buffers → 生成 gRPC stub + Kratos HTTP 路由

## 项目架构

遵循 Kratos 推荐的四层架构（类 Clean Architecture），依赖方向为 `server → service → biz → data`：

```
cmd/iwut-auth-center/    # 进程入口、Wire 组装、日志 & Tracer 初始化
internal/
  conf/                  # conf.proto 定义的配置结构（Bootstrap）
  server/                # HTTP/gRPC Server 创建、中间件装配、路由注册
  service/               # 实现生成的 gRPC/HTTP Server 接口，proto ↔ biz 参数转换
  biz/                   # 业务用例层：AuthUsecase、UserUsecase、Oauth2Usecase
  mail/                  # 邮件发送用例与 SMTP 模板
  data/                  # 仓储实现：MongoDB/Redis 读写、索引管理
  middleware/            # JWT 解析注入、审计信息采集
  util/                  # JWT 工具、SHA256、AppCenter 客户端、脱敏等
  api/                   # Git 子模块（iwut-api-proto），含 .proto 源文件与生成代码
  configs/               # 运行时 YAML 配置
```

## 三个服务域

| 服务 | Proto | 主要职责 |
|------|-------|---------|
| **Auth** | `api/auth_center/v1/auth/auth.proto` | 登录、注册、密码重置、邮件验证码、Token 刷新 |
| **User** | `api/auth_center/v1/user/user.proto` | 用户资料 CRUD、改密、销户、Consent 管理、Developer ID |
| **OAuth2** | `api/auth_center/v1/oauth2/oauth2.proto` | 授权码签发、Token 换取、用户资料开放接口、应用存储 |

## 认证体系

中间件通过 `X-Auth-Jwt-Type` 请求头区分三种调用身份，并将解析后的 Claims 注入 `context`：

| JWT 类型 | Header 值 | Claims 结构 | 用途 |
|---------|-----------|-------------|------|
| **Official** | `official` | `BaseAuthClaims`（uid, version, type, developerId） | 用户直接访问 |
| **OAuth** | `oauth` | `OAuthClaims`（jti, uid, scope, azp, aud, nonce） | 第三方 OAuth2 应用访问 |
| **Service** | `service` | `ServiceClaims`（serviceName, funcName） | 内部微服务间调用 |

- `/auth/` 路径和 `/oauth2/getToken` 跳过 JWT 检查
- Service 层通过 `jwtUtil.GetServiceClaims(ctx)` 获取 ServiceClaims，用于识别内部微服务调用；带此检查的接口是面向其他微服务开放的

## HTTP 错误编码约定

HTTP 响应始终返回 **200 状态码**，业务错误通过 body 中的 JSON 字段表达：

```json
{ "code": 404, "reason": "USER_NOT_FOUND", "message": "user not found", "traceId": "..." }
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `code` | number | HTTP 状态码 |
| `reason` | string（可选） | `ErrorReason` 枚举名称，与 gRPC 侧 Kratos Error 的 `reason` 字段一致，仅当错误匹配已知枚举时出现 |
| `message` | string | 人类可读的错误描述 |
| `traceId` | string（可选） | 链路追踪 ID |

gRPC 侧仍使用标准 gRPC status code 映射。

## 配置

- 配置文件：`configs/config.yaml`
- 环境变量前缀：`AuthCenter_`（会覆盖文件配置中同名字段）
- 配置结构由 `internal/conf/conf.proto` 定义，包含：Server、Data（MongoDB + Redis）、Jwt、Mail、Service

## 代码生成命令

```bash
make api      # proto → Go gRPC/HTTP stub + openapi.yaml
make config   # internal/conf/conf.proto → conf.pb.go
make wire     # Wire 依赖注入代码生成
make all      # 以上全部 + go generate + go mod tidy
```

修改 proto 后必须运行 `make api`；修改 `conf.proto` 后运行 `make config`；修改构造函数或 ProviderSet 后运行 `make wire`。

## Wire 依赖注入

`cmd/iwut-auth-center/wire.go` 组合所有 ProviderSet：

```
wire.Build(server.ProviderSet, data.ProviderSet, biz.ProviderSet,
           service.ProviderSet, util.ProviderSet, middleware.ProviderSet, newApp)
```

`wire_gen.go` 为自动生成文件，**不要手动编辑**。

## 编码约定

- **Repo 接口定义在 `biz` 层**，由 `data` 层实现——遵循依赖倒置
- **错误处理**：业务错误使用 Kratos `errors` 包 + `error_reason.proto` 中定义的枚举码；数据层将 MongoDB/Redis 错误映射为 Kratos 业务错误
- **日志**：使用 `log.NewHelper` + `log.WithContext(ctx)`，确保 trace 上下文传播
- **超时**：data 层方法普遍使用 `context.WithTimeout`（5~10s）
- **proto 响应包裹**：统一使用 `code`/`message`/`traceId`/`data` 结构
- **Service 层**使用 `util.GetProcesses[*TReply]()` 统一包装成功/失败分支与追踪信息
- **`api/` 是 Git 子模块**（`iwut-api-proto`），克隆后需 `git submodule update --init`

## 构建与部署

```bash
make build        # 生产构建
make dev-build    # 开发构建（保留调试符号）
```

- `dev.Dockerfile`：开发镜像，含 Delve 调试器，暴露端口 2345/8000/9000
- `prod.Dockerfile`：生产镜像，仅二进制 + configs，暴露 8000/9000
- `.cnb.yml`：CI/CD 流水线配置（使用 `prod.Dockerfile` 构建推送）
