# AGENTS.md — iWUT Auth Center

## Mission

This orphan branch is the new Auth Center implementation. It does not preserve
the old repository architecture or API behavior unless an accepted design says
so. Authoritative design lives outside this repository at `../../docs/`.

## Current work package

**UC-AUTH-026 — apply Application closure and issue close reauthentication proofs.** Read `../../docs/auth-center/briefs/UC-AUTH-026.md` as the active work-package input, then preserve the implemented authentication, OAuth, Session and governance behavior referenced by that brief. Deliver the native gRPC-only ApplicationClosure Apply/Get provider, permanent applicationId tombstone and stable receipt; enforce the tombstone at every selected UC014–019 final boundary; deliver Session-authenticated Begin/Complete with a fresh same-device P-256 challenge and fixed five-minute `app.close` proof; add Mongo schema/indexes, exact service permissions, config/Wire and real Auth/App verification. API generator inputs and outputs commit before the service gitlink. Do not implement App Center lifecycle, quota, Tester, OAuth client-slot mutation, UI/Gateway rollout, tombstone deletion or application recovery. Keep all commits local.

Preserve existing capabilities using the following lookup order only when the active brief requires their implementation details:

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

Governance work follows `../../docs/auth-center/briefs/UC-AUTH-021.md` through
`UC-AUTH-025.md`, the matching authoritative use cases, and
`../../docs/platform/contracts/account-owner-exit-v1.md`. Preserve the explicit
UC021 bootstrap consumption marker; there is no legacy bootstrap migration or
startup grant. Full administrator membership is the fixed four-permission bundle,
independent of reviewer permissions and Developer qualification.

Every USER is created with accountRevision=1 and developerRevision=0. Treat
missing or malformed revisions as invalid data; do not synthesize legacy defaults.
Account disable/restore increases accountRevision and all authentication consumers
check the generation. Auth-audience JWS carries account_revision and authorization
rechecks it in the final transaction, including profile CAS and governance writes.
Developer lifecycle changes use their own revision without revoking normal-user
Sessions. WITHDRAWN cannot be restored or reapplied in the first version.

UC024/025 share one pending lifecycle exit per authId and a durable Auth decision;
App owns the corresponding ownership barrier. Cross-service RPCs run outside
Mongo transaction callbacks. Cancellation may omit an unknown receipt after a lost
Prepare response; a supplied receipt and every COMMITTED receipt must match.
Closed-account cleanup never releases a developerHandle or device fingerprint,
never affects another association member, and never deletes an Application sector.
Use the independent termination ledger before reporting final termination; replay
and validate it before serving traffic after restoration. Cleanup acknowledgments,
not elapsed time or an empty dependency stub, determine completion. Production
readiness flags remain explicit operator declarations, not automatic guarantees.


Gateway routes and mobile secure-storage/UI delivery remain
separate work packages. Backend verification must not claim their completion.

UC020 follows `../../docs/auth-center/briefs/UC-AUTH-020.md`. Both exact DIRECT
methods authenticate with the current Session without refreshing LRU. Recheck at
the final authentication transaction, keep targets restricted to that authId,
and preserve explicit-target retry semantics. Candidate scans are bounded and
nextCursor may represent a filtered item; empty pages can still have continuation.
Never revoke a credential or OAuth family as a side effect.

## Code boundaries

UC014–019 additionally follow `../../docs/auth-center/briefs/UC-AUTH-014.md`
through `UC-AUTH-019.md`, and the OAuth/OIDC, App OAuth client, delegation and
route-policy contracts selected by those briefs. OAuth Domain/Port/UseCase live
under `internal/oauth/`; concrete storage, cryptography, clock and App provider
adapters remain under `internal/adapter/`. Preserve independent key purposes,
the shared authentication transaction fence, exact internal method allowlists,
current App/Catalog checks and default-closed public deployment gates.
OAuth supports TEST/STABLE/GREY through the same App provider. TEST alone requires
and binds a Tester episode; STABLE/GREY must have none. GREY cohort eligibility
belongs to App and is rechecked on every decision. Never fall back to another
channel/major, merge grants across channels or split Application sector/sub.
Scope Catalog is persistent when the explicit OAuth manifest is configured;
the old hardcoded adapter remains a development-only fallback.

```text
cmd/auth-center/             composition root only
internal/scope/domain/       protocol-independent business values
internal/scope/usecase/      UC orchestration
internal/scope/port/         consumer-owned interfaces
internal/adapter/catalog/    temporary hardcoded provider
internal/administrator/      fixed platform management membership
internal/account/            account lifecycle and authentication generation
internal/ownerexit/          durable cross-service exit coordination
internal/accountclosure/     dedicated closure proof, termination and cleanup
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
