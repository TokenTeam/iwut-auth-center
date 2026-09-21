# AGENTS.md — iWUT Auth Center

## Mission

This orphan branch is the new Auth Center implementation. It does not preserve
the old repository architecture or API behavior unless an accepted design says
so. Authoritative design lives outside this repository at `../../docs/`.

## Current work package

**UC-AUTH-002 Batch Get Developer Statuses.** Before changing behavior, read:

1. `../../docs/auth-center/use-cases/UC-AUTH-002-batch-get-developer-statuses.md`
2. `../../docs/platform/contracts/auth-developer-status-v1.md`
3. `../../docs/auth-center/open-questions.md`

Scope:

- native gRPC service `auth_center.v1.developer_status.DeveloperStatusDirectory`;
- Kratos lifecycle and `github.com/goforj/wire` composition root;
- Domain, UseCase, port and adapters separated by responsibility;
- Auth-owned MongoDB `auth_principals` repository and unique `authId` index;
- real MongoDB and real-listener E2E through the generated gRPC client.

Temporary explicit gaps:

- no production service-identity credential or allowlist interceptor;
- no HTTP/Gateway/gRPC-Web route;
- no catalog mutation, OAuth or user capability.

Keep the design status `PROPOSED` and implementation status `IN_PROGRESS` until
the service-identity and allowlist work package is complete. Principal creation
and Developer status mutation remain separate future use cases.

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
