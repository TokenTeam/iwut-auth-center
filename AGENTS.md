# AGENTS.md — iWUT Auth Center

## Mission

This orphan branch is the new Auth Center implementation. It does not preserve
the old repository architecture or API behavior unless an accepted design says
so. Authoritative design lives outside this repository at `../../docs/`.

## Current work package

**Internal service identity + UC-AUTH-003 Resolve System Principal.** Before changing behavior, read:

1. `../../docs/platform/adr/ADR-PLAT-002-internal-service-identity-jws.md`
2. `../../docs/platform/contracts/trusted-service-identity-v1.md`
3. `../../docs/auth-center/use-cases/UC-AUTH-003-resolve-system-principal.md`
4. `../../docs/platform/contracts/auth-system-principal-v1.md`

Scope:

- caller-signed service JWS middleware and fixed RPC permission mapping;
- native gRPC service `auth_center.v1.system_principal.SystemPrincipalDirectory`;
- Kratos lifecycle and `github.com/goforj/wire` composition root;
- Auth-owned MongoDB SYSTEM principal provision and purpose uniqueness;
- real MongoDB and real-listener E2E through generated clients.

No HTTP/Gateway/gRPC-Web route. Reviewer grant/revoke, ordinary user provision,
Developer status mutation and Scope Catalog mutation remain separate UCs.

## Code boundaries

```text
cmd/auth-center/             composition root only
internal/scope/domain/       protocol-independent business values
internal/scope/usecase/      UC orchestration
internal/scope/port/         consumer-owned interfaces
internal/adapter/catalog/    temporary hardcoded provider
internal/developer/domain/   principal/status business values
internal/developer/usecase/  batch query orchestration
internal/developer/port/     principal repository port
internal/adapter/mongo/      Auth-owned MongoDB repository
internal/adapter/transport/  Proto/gRPC conversion and Kratos server
internal/config/             environment parsing and validation
api/                        pinned independent API repository worktree
```

Domain must not import Kratos, gRPC, generated Proto, configuration, database
drivers or transport encodings. UseCase depends only on its Domain and ports.
Only the composition root may know configuration and concrete adapters.

## Generated code

- Never hand-edit `api/gen/` or `cmd/auth-center/wire_gen.go`.
- Regenerate Proto with `make -C api proto-gen`.
- Regenerate Wire with `make generate`.
- Commit generator input and output together.

## Verification

Run `make check`, `make test-race`, and `make test-mongo`. The provider E2E must
use real MongoDB, a real Kratos gRPC listener, generated clients and the Wire
composition root.

Do not push. Keep API and Auth commits local until the user chooses a
publication batch.
