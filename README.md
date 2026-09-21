# iWUT Auth Center — Scope catalog and developer status

This orphan-branch implementation bootstraps Auth Center from the authoritative
design in `../../docs/auth-center/`. It exposes the full scope catalog snapshot
and the current Developer status projection to internal services through native
gRPC.

The current catalog remains deliberately hard-coded. Developer status is read
from Auth-owned MongoDB collection `auth_principals`. The service is **not
production-ready**: trusted service identity and authorisation are still
required before either endpoint may be exposed outside a local/test environment.

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

## Temporary implementation boundary

- `internal/adapter/catalog` is an in-memory hard-coded adapter; it is unrelated
  to the Mongo-backed principal repository.
- Startup ensures the unique `authId` index in `auth_principals`; it does not
  create principals or mutate Developer status.
- `cmd/auth-center/e2e_test.go` starts the real Wire-composed Kratos server and
  calls both APIs with generated gRPC clients against real MongoDB when
  `MONGODB_INTEGRATION_URI` is set. `make test-mongo` provisions that database.
- The endpoint currently has no service-identity interceptor. Deployment must
  remain blocked until the agreed internal identity contract is implemented.
