# AGENTS.md — iWUT Auth Center

## Mission

This orphan branch is the new Auth Center implementation. It does not preserve
the old repository architecture or API behavior unless an accepted design says
so. Authoritative design lives outside this repository at `../../docs/`.

## Current work package

**UC-AUTH-004–013: reviewer administration, user profile, device authentication, Session-to-JWS issuance, email registration/binding, email login and Developer self-enrollment.** Before changing behavior, read:

1. `../../docs/auth-center/briefs/UC-AUTH-013.md` and `../../docs/platform/contracts/auth-developer-application-v1.md`, then `../../docs/auth-center/briefs/UC-AUTH-012.md` and `../../docs/platform/contracts/auth-email-login-v1.md`, then `../../docs/auth-center/briefs/UC-AUTH-011.md`, `../../docs/platform/contracts/auth-email-binding-v1.md` and its public vectors; preserve UC004–010 behavior.
2. `../../docs/auth-center/briefs/UC-AUTH-004.md` and the corresponding `../../docs/auth-center/briefs/UC-AUTH-005.md` through `UC-AUTH-010.md`.
3. `../../docs/platform/contracts/auth-device-session-v1.md` and its test vectors.
4. `../../docs/platform/contracts/trusted-identity-v1.md` for profile user authentication.
5. `../../docs/platform/contracts/trusted-service-identity-v1.md` for existing internal methods.

Scope:

- preserve caller-signed service JWS middleware and existing fixed RPC permission mapping;
- select authentication by exact full method; no anonymous package wildcard;
- HTTP/JSON and native gRPC user profile and device authentication methods;
- internal service methods remain native gRPC only; HTTP routing follows
  `../../docs/platform/contracts/auth-center-api-routing.md`;
- Kratos lifecycle and `github.com/goforj/wire` composition root;
- Auth-owned MongoDB profile, credential, operation, Session and student association state;
- real MongoDB replica-set transactions and real-listener E2E through generated clients.

UC010 additionally follows `../../docs/platform/contracts/auth-session-identity-issuance-v1.md`.

Gateway routes and mobile secure-storage/UI delivery remain
separate work packages. Backend verification must not claim their completion.

## Code boundaries

```text
cmd/auth-center/             composition root only
internal/scope/domain/       protocol-independent business values
internal/scope/usecase/      UC orchestration
internal/scope/port/         consumer-owned interfaces
internal/adapter/catalog/    temporary hardcoded provider
internal/developer/domain/   principal/status business values
internal/developer/usecase/  batch query and self-enrollment orchestration
internal/developer/port/     principal and enrollment repository ports
internal/adapter/mongo/      Auth-owned MongoDB repository
internal/adapter/transport/  Proto/HTTP/gRPC conversion and Kratos servers
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

UC004 reviewer mutations and bootstrap must use the shared authentication transaction
fence. Audit insertion and permissions CAS commit together. Bootstrap is an explicit
database-only command with a durable global consumed marker, never a startup grant.

UC011 email operations share the authentication transaction fence. Keep email
registration atomic with USER, device, association, Session, binding and audit.
Association migration must include REGISTER_WITH_EMAIL snapshots. SMTP runs only
after confirmed operation commit, never inside transaction retries. Transport
must distinguish an absent Session carrier from every invalid supplied carrier.
UC012 reuses those facilities and extends all Session consumers for EMAIL_CODE_AND_DEVICE.
UC013 uses the same transaction fence for current Session/binding/status confirmation,
principal activation, unique handle ownership/activation history and immutable audit. Never restore
PENDING/REJECTED/SUSPENDED through Apply; preserve nullable historical activation time.
Apply requires a valid 3–32 ASCII developerHandle and stores only canonical lowercase.
Keep ownership authoritative in auth_developer_handles (unique authId and handle),
with immutable activation/audit handle evidence. Lost or mismatched ownership fails
closed, never becomes a legacy rename. APPROVED legacy users can explicitly claim
once after email/recovery checks, preserving activation history. Upgrade audit to
unique (subjectAuthId, action) before dropping the old single-subject unique index.
No name release, public name routing, new JWS claims or App ownership changes.
Developer enrollment and recovery-ready flags default off; operator readiness is not
an automatic UI health check. No additional reviewer/admin privileges are granted.
Gateway routes and mobile clients remain separate delivery packages.
