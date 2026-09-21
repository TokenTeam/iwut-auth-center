# AGENTS.md — iWUT Auth Center

## Mission

This orphan branch is the new Auth Center implementation. It does not preserve
the old repository architecture or API behavior unless an accepted design says
so. Authoritative design lives outside this repository at `../../docs/`.

## Current work package

**UC-AUTH-001 Get Scope Catalog Snapshot.** Before changing behavior, read:

1. `../../docs/auth-center/use-cases/UC-AUTH-001-get-scope-catalog-snapshot.md`
2. `../../docs/platform/contracts/auth-scope-catalog-v1.md`
3. `../../docs/auth-center/open-questions.md`

Scope:

- native gRPC service `auth_center.v1.scope_catalog.ScopeCatalog`;
- Kratos lifecycle and `github.com/goforj/wire` composition root;
- Domain, UseCase, port and adapters separated by responsibility;
- a deterministic hardcoded catalog adapter for local development and E2E;
- real-listener E2E through the generated gRPC client.

Temporary explicit gaps:

- no MongoDB client, schema, migration or persistence;
- no production service-identity credential or allowlist interceptor;
- no HTTP/Gateway/gRPC-Web route;
- no catalog mutation, OAuth or user capability.

The hardcoded adapter is not the production authority described by BR-SCP-001.
Keep the design status `PROPOSED` and implementation status `IN_PROGRESS` until
the service-identity and persistent authority work packages are complete.

## Code boundaries

```text
cmd/auth-center/             composition root only
internal/scope/domain/       protocol-independent business values
internal/scope/usecase/      UC orchestration
internal/scope/port/         consumer-owned interfaces
internal/adapter/catalog/    temporary hardcoded provider
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

Run `make check`. The E2E is self-contained and must use a real Kratos gRPC
listener, generated client, Wire composition root and the hardcoded catalog.

Do not push. Keep API and Auth commits local until the user chooses a
publication batch.
