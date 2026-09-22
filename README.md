# iWUT Auth Center — internal authority services

This orphan-branch implementation bootstraps Auth Center from the authoritative
design in `../../docs/auth-center/`. It exposes the full scope catalog snapshot
the current Developer status projection and Auth-owned SYSTEM principals to
authorized internal services through native gRPC.

The current catalog remains deliberately hard-coded. Developer and SYSTEM
principals are read from Auth-owned MongoDB collection `auth_principals`.
Every business RPC is protected by caller-signed service JWS authentication and
a fixed operation permission allowlist.

## Prerequisites and build

- Go 1.24 or newer.
- The pinned Proto toolchain printed by `make -C api proto-tools` when changing
  API definitions.

```bash
make generate
make check
make test-race
make test-mongo
make run
```

`make run` starts a native gRPC listener on `:9000` by default. There is no HTTP
route and no gRPC-Web exposure in Auth Center; an eventual Gateway/Traefik edge
owns external protocol mapping.

## Environment

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `AUTH_CENTER_GRPC_ADDR` | no | `:9000` | Native gRPC listen address |
| `AUTH_CENTER_MONGO_URI` | no | `mongodb://127.0.0.1:27017` | MongoDB connection URI |
| `AUTH_CENTER_MONGO_DATABASE` | no | `iwut_auth_center` | Auth-owned database name |
| `AUTH_CENTER_SERVICE_CALLERS_B64` | yes | — | strict standard Base64 of the trusted-service-identity-v1 caller registry JSON |
| `AUTH_CENTER_SERVICE_IDENTITY_MAX_TTL` | no | `2m` | maximum accepted `exp - iat` |
| `AUTH_CENTER_SERVICE_IDENTITY_CLOCK_SKEW` | no | `30s` | accepted clock skew |

## Temporary implementation boundary

- `internal/adapter/catalog` is an in-memory hard-coded adapter; it is unrelated
  to the Mongo-backed principal repository.
- Startup ensures the unique `authId` and SYSTEM purpose indexes and idempotently
  provisions the known non-login SYSTEM principals. It never creates ordinary
  users or mutates Developer status.
- `cmd/auth-center/e2e_test.go` starts the real Wire-composed Kratos server and
  calls both APIs with generated gRPC clients against real MongoDB when
  `MONGODB_INTEGRATION_URI` is set. `make test-mongo` provisions that database.
- Private keys are never accepted by Auth. Caller public keys, permissions and
  purpose allowlists come only from `AUTH_CENTER_SERVICE_CALLERS_B64`; token
  supplied key material or permissions are ignored/rejected.
