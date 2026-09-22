# AGENTS.md — iWUT Auth Center

## Mission

This orphan branch is the new Auth Center implementation. It does not preserve
the old repository architecture or API behavior unless an accepted design says
so. Authoritative design lives outside this repository at `../../docs/`.

## Current work package

**UC-AUTH-005–009: user profile, device registration/login, Session and credential revocation.** Before changing behavior, read:

1. The corresponding `../../docs/auth-center/briefs/UC-AUTH-005.md` through `UC-AUTH-009.md`.
2. `../../docs/platform/contracts/auth-device-session-v1.md` and its test vectors.
3. `../../docs/platform/contracts/trusted-identity-v1.md` for profile user authentication.
4. `../../docs/platform/contracts/trusted-service-identity-v1.md` for existing internal methods.

Scope:

- preserve caller-signed service JWS middleware and existing fixed RPC permission mapping;
- select authentication by exact full method; no anonymous package wildcard;
- native gRPC user profile and device authentication methods;
- Kratos lifecycle and `github.com/goforj/wire` composition root;
- Auth-owned MongoDB profile, credential, operation, Session and student association state;
- real MongoDB replica-set transactions and real-listener E2E through generated clients.

Gateway routes, Session-to-JWS issuance and mobile secure-storage/UI delivery remain
separate work packages. Backend verification must not claim their completion.

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
