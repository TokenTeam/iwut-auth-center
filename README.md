# iWUT Auth Center — UC-AUTH-001 bootstrap

This orphan-branch implementation bootstraps Auth Center from the authoritative
design in `../../docs/auth-center/`. Its first vertical slice returns the full
scope catalog snapshot to internal services through native gRPC.

The current catalog is deliberately hard-coded so the API, Kratos process,
Wire composition root and real-listener E2E path can be proven before MongoDB
is introduced. It is **not production-ready**: trusted service identity and
authorisation are still required before the endpoint may be exposed outside a
local/test environment.

## Prerequisites and build

- Go 1.24 or newer.
- The pinned Proto toolchain printed by `make -C api proto-tools` when changing
  API definitions.

```bash
make generate
make check
make test-race
make run
```

`make run` starts a native gRPC listener on `:9000` by default. There is no HTTP
route and no gRPC-Web exposure in Auth Center; an eventual Gateway/Traefik edge
owns external protocol mapping.

## Environment

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `AUTH_CENTER_GRPC_ADDR` | no | `:9000` | Native gRPC listen address |

## Temporary implementation boundary

- `internal/adapter/catalog` is an in-memory hard-coded adapter, not MongoDB.
- `cmd/auth-center/e2e_test.go` starts the real Wire-composed Kratos server and
  calls it with the generated gRPC client.
- The endpoint currently has no service-identity interceptor. Deployment must
  remain blocked until the agreed internal identity contract is implemented.
