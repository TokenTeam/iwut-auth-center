# iWUT Auth Center

## 2026-10-13 email account v3

UC006/011/031 and `auth-email-account-v3` are accepted; briefs were regenerated
before implementation. V3 registers a verified email, platform password and
background device credential atomically. Every account has 1–10 globally unique
verified addresses and exactly one login/recovery role. Adding/removing non-login
addresses does not require a password; switching roles does, without clearing
existing devices or Sessions. The current login binding, not mere email ownership,
is used by email-code login, OAuth email disclosure and Developer enrollment.

Campus certification is derived only from current exact `@whut.edu.cn` bindings.
Its timestamp is the earliest verification among current campus bindings. Campus
verification routes are ADD aliases; they neither write nor trust old permanent
facts. Removing the last campus basis immediately removes disclosure while
preserving OAuth consent and Application pairwise sub. Auth never manages App
benefit counters or receipt ledgers.

Old no-email registration and v1 BeginSetEmail/CompleteSetEmail are permanently
retired (gRPC UNIMPLEMENTED; no HTTP routes). The retained v1 Get is a projection
of the primary binding/login-role revision with no pending proposal. Device login
signing bytes are unchanged. No deployment/production migration is performed;
missing/malformed directory/password records are not repaired or defaulted.

This is an incomplete combined password delivery: default password login, reset,
reliable notification delivery and public password services remain incomplete.
UC009/025/026 danger gates are implemented and verified in the full real Mongo/Wire race suite:
current-only legacy revocation and current-password plus registered-device proof
for account/App closure. PasswordManagement/PasswordLogin services
are not registered. Do not enable the new model in production yet. Gateway,
Console and mobile UI delivery are independent work packages.

### Development gate for the v3 email runtime

`AUTH_PASSWORD_ENABLED` defaults false. V3 additionally requires enabled user
endpoints and `AUTH_EMAIL_BINDING_ENABLED=true`, SMTP settings, and these explicit
inputs:

- `AUTH_PASSWORD_OPERATION_HMAC_KEY`: canonical standard Base64, independent random 32-byte key.
- `AUTH_PASSWORD_BLOCKLIST_FILE`, `AUTH_PASSWORD_BLOCKLIST_VERSION`, `AUTH_PASSWORD_BLOCKLIST_SOURCE`, `AUTH_PASSWORD_BLOCKLIST_SHA256`: pinned nonempty regular file of whole NFC-password SHA-256 digests (64 lowercase hex + LF), at most 1,000,000 unique lines. Not an account password verifier.
- `AUTH_PASSWORD_READINESS_CONFIRMED=true`: operator declaration, not automatic evidence that remaining delivery is complete.
- Optional `AUTH_PASSWORD_ARGON_MEMORY_KIB`, `AUTH_PASSWORD_ARGON_ITERATIONS`, `AUTH_PASSWORD_ARGON_PARALLELISM`: reviewed defaults 19456/2/1 and enforced bounds.

The campus alias additionally uses `AUTH_CAMPUS_CERTIFICATION_ENABLED=true` and
the ADD email key; retired `AUTH_CAMPUS_CERTIFICATION_CODE_KEY` is ignored, not a
startup rejection. Existing email-code login can be enabled against a valid v3
directory without enabling registration. A populated legacy one-owner-binding
schema fails startup rather than undergoing an automatic migration or deletion.

This orphan-branch implementation bootstraps Auth Center from the authoritative
design in [`TokenTeam/iwut-docs`](https://github.com/TokenTeam/iwut-docs/tree/main/auth-center). It exposes the full scope catalog snapshot
the current Developer status projection and Auth-owned SYSTEM principals to
authorized internal services through native gRPC.

The OAuth scope catalog is persisted and seeded from an explicit deployment
manifest when OAuth is enabled; the hard-coded catalog is only a development
fallback. Developer and SYSTEM principals are read from Auth-owned MongoDB
collection `auth_principals`.
Internal business RPCs use caller-signed service JWS and a fixed permission
allowlist. The optional UC005–009 user endpoints add profile editing, app-managed
email registration/background device login, Session revocation and credential revocation over both
HTTP/JSON and native gRPC. Their
authentication is selected by exact full method, following
[`auth-device-session-v1`](https://github.com/TokenTeam/iwut-docs/blob/main/platform/contracts/auth-device-session-v1.md).

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

`make run` starts HTTP on `:8000` and native gRPC on `:9000` by default.
User HTTP routes require the user-endpoint switch below. Gateway/Traefik owns
the public service prefix and gRPC-Web mapping.

## Container image

Build the production image from the repository root:

```bash
docker build -t iwut-auth-center .
```

The Dockerfile uses an Alpine Go builder and a separate Alpine runtime.
`CGO_ENABLED=0` produces a static executable, so it depends on neither glibc nor
musl at runtime. The runtime installs CA certificates for MongoDB, SMTP, App
Center and OTLP TLS connections, runs as the unprivileged UID/GID `10001`, and
exposes the default HTTP and gRPC ports `8000` and `9000`.

Start the service with its environment and mounted configuration, key and CA
files. Account closure deployments must also mount a writable durable directory
and point their configured ledger path at it; `/var/lib/iwut-auth-center` is
created for that purpose.

```bash
docker run --rm --env-file auth-center.env \
  -p 8000:8000 -p 9000:9000 \
  iwut-auth-center
```

The image entrypoint is `auth-center`; no argument starts the service. Explicit
maintenance commands remain available, for example
`iwut-auth-center bootstrap-platform-admin ...` and
`iwut-auth-center reconcile-account-closures`. Health probes should call HTTP
`GET /livez` and `GET /readyz`, or the standard gRPC health service.

## Environment

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `AUTH_CENTER_HTTP_ADDR` | no | `:8000` | HTTP listen address |
| `AUTH_CENTER_GRPC_ADDR` | no | `:9000` | Native gRPC listen address |
| `AUTH_CENTER_MONGO_URI` | no | `mongodb://127.0.0.1:27017` | MongoDB connection URI |
| `AUTH_CENTER_MONGO_DATABASE` | no | `iwut_auth_center` | Auth-owned database name |
| `AUTH_CENTER_SERVICE_CALLERS_B64` | yes | — | strict standard Base64 of the trusted-service-identity-v1 caller registry JSON |
| `AUTH_CENTER_SERVICE_IDENTITY_MAX_TTL` | no | `2m` | maximum accepted `exp - iat` |
| `AUTH_CENTER_SERVICE_IDENTITY_CLOCK_SKEW` | no | `30s` | accepted clock skew |
| `AUTH_CENTER_LOG_LEVEL` | no | `INFO` | JSON log level: `DEBUG`, `INFO`, `WARN` or `ERROR` |
| `AUTH_CENTER_OTLP_GRPC_ENDPOINT` | no | — | OTLP gRPC collector in strict `host:port` form; exporters stay disabled when omitted |
| `AUTH_CENTER_OTLP_INSECURE` | no | `false` | use plaintext OTLP gRPC; valid only with an endpoint |
| `AUTH_CENTER_TRACE_SAMPLE_RATIO` | no | `0.1` | parent-based root trace sampling ratio from `0` through `1` |
| `AUTH_CENTER_METRIC_EXPORT_INTERVAL` | no | `30s` | OTLP metric export interval, at least `1s` |

HTTP `GET`/`HEAD /livez` reports process liveness. `GET`/`HEAD /readyz`
dynamically pings MongoDB and returns 503 until the dependency is available.
Native gRPC exposes the standard unauthenticated health service. Shutdown has a
five-second telemetry flush budget. Request telemetry uses fixed route/RPC
operations and stable result labels; it never records headers, paths, request or
response bodies, OAuth material, cookies, email addresses or profile values.

## Temporary implementation boundary

- OAuth's scope catalog and the profile field catalog are separate validated
  deployment manifests. The accepted production field/scope lists are checked
  into `configs/`; the academic-year schedule is Mongo-authoritative and starts
  from the deterministic September 1 baseline.
- Startup ensures the unique `authId` and SYSTEM purpose indexes and idempotently
  provisions the known non-login SYSTEM principals. Ordinary USER records are created only by atomic registration, including an empty
  profile at revision 1. Startup never mutates Developer status.
- `cmd/auth-center/e2e_test.go` starts the real Wire-composed Kratos server and
  calls both APIs with generated gRPC clients against real MongoDB when
  `MONGODB_INTEGRATION_URI` is set. `make test-mongo` provisions that database.
- Caller private keys are never accepted by Auth. Caller public keys, permissions and
  purpose allowlists come only from `AUTH_CENTER_SERVICE_CALLERS_B64`; token
  supplied key material or permissions are ignored/rejected.

## Enable user endpoints

Set `AUTH_USER_ENDPOINTS_ENABLED=true` for retained UC005/007–009 and the shared user runtime; UC011 registration has its independent email switch. It defaults to false
for deployments using only the existing internal methods. Enabling it requires
all configuration below; missing or invalid values fail startup. MongoDB must be
a replica set (a single member is sufficient) or a transaction-capable cluster.
Startup probes a real transaction before serving requests.

| Variable | Required when enabled | Meaning |
| --- | --- | --- |
| `AUTH_AUTHENTICATION_SERVICE_ID` | yes | Stable deployment identity, for example `iwut-auth-center:prod`; clients must use the same value |
| `AUTH_SESSION_TTL` | yes | Positive whole-millisecond Go duration; `720h` is an example, not a default |
| `AUTH_PROFILE_CATALOG_FILE` | yes | JSON file with a `definitions` array following UC005; an explicitly empty array is valid |
| `AUTH_USER_IDENTITY_ISSUER` | yes | Trusted-user JWS issuer |
| `AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON` | yes | JSON object mapping each issuer `kid` to a PEM public-key file path; RSA 2048 bits minimum |
| `AUTH_USER_IDENTITY_MAX_TTL` | no | Maximum accepted user JWS lifetime, default `5m` |
| `AUTH_USER_IDENTITY_CLOCK_SKEW` | no | Accepted user JWS clock skew, default `30s` |

Optional bounded authentication settings are `AUTH_MAX_PENDING_OPERATIONS=10000`,
`AUTH_MAX_FAILED_ATTEMPTS=5`, `AUTH_BEGIN_GLOBAL_PER_MINUTE=600`,
`AUTH_COMPLETE_GLOBAL_PER_MINUTE=1200`, `AUTH_BEGIN_SOURCE_PER_MINUTE=30`,
`AUTH_COMPLETE_LOCATOR_PER_MINUTE=60`, `AUTH_RATE_MAX_BUCKETS=4096`, and
`AUTH_MAX_MESSAGE_BYTES=16384`. Registration and login share one in-process
limiter. Source means the socket peer, never an untrusted forwarded header.
The Session limit is fixed at 10 per account; valid checks synchronously update
LRU order. No Session validity cache bypasses current principal/credential state.

Profile RPCs require `x-iwut-identity` with a trusted-user JWS for
`iwut-auth-center`. Device proof RPCs are explicitly bounded anonymous methods.
The accepted production field and scope manifests are provided in
`configs/profile-fields.production.json` and `configs/oauth-scopes.production.json`.
Academic-year progression is provisioned in Mongo with a deterministic September 1
baseline and is not loaded from a deployment file. `AUTH_ACADEMIC_CALENDAR_FILE` is
retired and ignored if it remains in an environment. The schedule is a platform
progression policy, not an official university fact or proof of enrollment.
`RevokeCurrentSession` accepts only its `x-iwut-session` token and succeeds
idempotently even when that correctly formatted token is expired or unknown.
`RevokeOwnCredential` requires a currently valid Session in that header.
It can revoke only the credential used by that Session. Every other valid-shaped
target returns `CREDENTIAL_REAUTH_REQUIRED` (403), before looking up ownership.
UC032 provides bounded, no-touch credential listing, optional labels with CAS,
and revocation of one other credential using the current Session, current
password and a fresh signature from that Session's device key. A Session alone
cannot revoke another credential. The four native gRPC/HTTP methods belong to
`auth_center.v1.credential_management.CredentialManagementService`.
`AUTH_CREDENTIAL_MANAGEMENT_ENABLED` defaults to false; enabling it requires
the user endpoints and the shared password runtime. Its independent
`AUTH_CREDENTIAL_MANAGEMENT_GLOBAL_PER_MINUTE`,
`AUTH_CREDENTIAL_MANAGEMENT_SOURCE_PER_MINUTE`,
`AUTH_CREDENTIAL_MANAGEMENT_ACCOUNT_PER_MINUTE`, and
`AUTH_CREDENTIAL_MANAGEMENT_MAX_BUCKETS` settings default to 600, 120, 30,
and 4096 (all finite positive values). Operations expire after five minutes,
share a five-failure password/signature budget, and retain replay state for
24 hours. Turning off the routes keeps bounded cleanup of persisted operations.
Gateway routes, old-device authorization and mobile key storage/UI remain
separate deliveries. Email recovery through a new device is implemented by UC012 below. These are app-managed device
keys, not WebAuthn Passkeys.

## HTTP/JSON interface

The Wire composition root starts both Kratos servers and reuses the same services
and authentication dispatch. Set `AUTH_CENTER_HTTP_ADDR` (default `:8000`) and
`AUTH_CENTER_GRPC_ADDR` (default `:9000`). `AUTH_USER_ENDPOINTS_ENABLED=false`
leaves the HTTP user routes unregistered. Internal scope, developer, SYSTEM and
Session-to-JWS APIs remain native gRPC only.

The authoritative route mapping is [Auth API routing](https://github.com/TokenTeam/iwut-docs/blob/main/platform/contracts/auth-center-api-routing.md).
Proto HTTP annotations use service-local `/v1/...` paths, like App Center;
`/auth-center` belongs to Gateway prefix stripping and is not accepted by Auth.
Gateway routing is a separate delivery.

| Method | Service-local path | RPC |
| --- | --- | --- |
| POST | `/v1/device-logins` | BeginDeviceLogin |
| POST | `/v1/device-logins/{operation_id}/completion` | CompleteDeviceLogin |
| DELETE | `/v1/sessions/current` | RevokeCurrentSession |
| DELETE | `/v1/users/me/credentials/{credential_id}` | RevokeOwnCredential |
| GET | `/v1/users/me/profile` | GetOwnProfile |
| PATCH | `/v1/users/me/profile` | EditOwnProfile |
| GET | `/v1/user-profile-schema` | GetProfileEditingSchema |

POST/PATCH require `Content-Type: application/json` and standard ProtoJSON:
`bytes` use Base64, `int64` output uses decimal strings, timestamps use RFC3339.
For example, editing uses `{"expectedRevision":"1","set":[{"key":"field.key","value":{"stringValue":"value"}}]}`.
Completion operation IDs and credential IDs come from the path. The existing
`x-iwut-session` / `x-iwut-identity` rules apply equally to HTTP headers.
Query parameters and GET/DELETE bodies are rejected. Compressed request bodies
are unsupported. Input rejects unknown/duplicate fields and conflicting oneof
values; body reads are bounded before allocation. Authentication bodies default
to 16 KiB; profile edits allow 128 KiB. Business capacity checks still apply.
All responses carry `Cache-Control: no-store`; device/email login completions
return 201, email signup and campus completion return 200 (revocation returns `{}`). Error JSON
preserves the same stable reason as gRPC, with UC-specific 400/401/403/404/409/
413/429/503 status mapping. Parser errors never echo raw submitted values.

`cmd/auth-center/http_e2e_test.go` runs against the real Wire process and MongoDB,
covering the retained routes, retired no-email 404, generated HTTP clients, strict JSON, Session headers,
profile CAS, revocation retries, and isolation of internal methods. The existing
gRPC provider tests exercise the same running composition root.

## Retired association configuration and storage

AUTH_ASSOC_KEY_VERSION, AUTH_ASSOC_ENCRYPT_KEY, AUTH_ASSOC_LOOKUP_KEY and their
AUTH_ASSOC_PREVIOUS_* counterparts are ignored. Malformed leftovers do not block
startup. There are no association group/member writes, encryption, startup
migration or full-scan maintenance prerequisites. This undeployed system has no
production association migration; startup does not silently delete old development
data or turn old school declarations into campus certification.

USER initialization, credentials, operations and Sessions remain Auth-owned,
with unique IDs/fingerprints/token digests and the shared authentication
transaction fence. Session secrets, device private keys, school passwords,
student numbers and whole signing payloads are not persisted. The registration
API only accepts verified email plus the background device proof. Email-key
cold updates, JWS rotation and UC025 termination-ledger restore checks remain
required under their own contracts; they are not association migration.

## Session-to-user-identity issuance (UC010)

`AUTH_IDENTITY_ISSUANCE_ENABLED=true` enables the internal native gRPC method
`/auth_center.v1.identity.UserIdentityService/IssueUserIdentityFromSession`.
It defaults to false and requires `AUTH_USER_ENDPOINTS_ENABLED=true`.
The request carries only its exact destination `audience`; `authorization` must
contain a registered service Bearer JWS, and `x-iwut-session` must contain exactly
one canonical Session token. Neither credential can substitute for the other.
There is no HTTP/gRPC-Web or terminal route for this method.

Add `auth.identity.issue` and a nonempty unique `identityAudiences` array to the
Gateway's caller registration. Allowed audiences are `iwut-auth-center` and
`iwut-app-center`. Other service registrations omit this field and gain no new
permission. An audience list without the permission is a startup error.

| Variable | Meaning |
| --- | --- |
| `AUTH_USER_IDENTITY_SIGNING_KID` | Required signing kid, matching a configured local verifier public key |
| `AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64` | Required canonical standard Base64 of PKCS#1/PKCS#8 RSA private-key PEM, at least 2048 bits |
| `AUTH_USER_IDENTITY_TTL` | Default `60s`; 1–300 whole seconds, no greater than the local verifier maxTTL |

Issuer uses `AUTH_USER_IDENTITY_ISSUER`. Signing keys must differ from every
registered service public key; comparison uses actual RSA public material, not
kid labels. Provision the same accepted issuer/public key/maxTTL at each target.
The Auth deployment validates its own verifier at startup; cross-service TTL/key
alignment is a deployment contract, not automatic configuration discovery.
Rotate by first adding the new public key at all consumers, then switching signer
kid/private key. Keep the old public key through the longest issued lifetime,
clock skew and in-flight window before removing it. Never log these secrets,
Session tokens, request authentication metadata, or returned JWS.

Each issue reads the current Session, credential and ACTIVE USER with capabilities
inside the shared Mongo authentication transaction. Conditional record writes
also conflict with direct capability/disable updates. RS256 signing runs inside
that transaction and monotonic `lastUsedAt` commits only after signing succeeds.
A candidate is returned only after confirmed commit and a fresh expiry check;
unknown commit results fail closed and may require a fresh RPC. No token result
is persisted or cached. A signed result authorized before revocation remains
valid through its short lifetime and consumer clock skew.

The Auth audience receives the four UC021 management permissions; the App audience receives
`app.profile.review` and `app.version.review`, plus a valid existing Developer
status when present.
These are intersections with current authoritative permissions, never grants.
Ordinary users get `permissions: []` and no Developer claim. Session expiry bounds
`exp`, so issuing never extends a Session. There is no Redis requirement.

`cmd/auth-center/identity_issuance_e2e_test.go` covers real registration, production
Wire/RSA service identity, native gRPC/Mongo issuance, real target profile
verification, audience authorization and current capabilities/revocation. The
Mongo integration suite additionally injects signer and unknown-commit failures
and exercises concurrent capability/revocation writes. Tests log bounded local
RSA and RPC/Mongo measurements; they are not production capacity estimates.
Gateway routing is verified separately by the Gateway protocol E2E suite.

## Application review permission management (UC-AUTH-004)

User endpoint runtime also registers `ReviewerPermissionService` in both native
gRPC and HTTP. Gateway uses SESSION policy with `iwut-auth-center` audience:

- `GET /v1/users/{subject_auth_id}/application-review-permissions` returns both
  `app.profile.review` and `app.version.review` with independent `granted` values,
  sorted by permission, and one shared `permissionRevision`.
- `PUT /v1/users/{subject_auth_id}/application-review-permissions/{permission}`
  changes exactly one of those permissions. Its body contains `action`,
  `expectedRevision`, and `reason`; path values override corresponding body fields.
  Unknown permissions, management capabilities and OAuth scopes are rejected.
- Legacy `GET /v1/users/{subject_auth_id}/reviewer-permission` reads only the
  version-review state; `reviewer` is never the OR of both permissions.
- `PUT /v1/users/{subject_auth_id}/reviewer-permission` accepts `action` (`1` grant,
  `2` revoke), positive `expectedRevision`, and a reason (trimmed, 1–1024 UTF-8
  bytes). The path owns the subject ID. Both return `subjectAuthId`, `reviewer`,
  and `permissionRevision` (ProtoJSON decimal string).

A verified user JWS must contain `auth.reviewer.manage`; all four operations also
confirm the actor's current ACTIVE USER state, complete UC021 bundle and consumed initialization in Mongo. Only
ACTIVE USER subjects are eligible. Repeated actions and stale revisions return
409; query current state after an uncertain response before deciding to retry.
Each mutation preserves the other review permission and all unrelated capabilities.
Concurrent changes to different permissions still compete on the same revision.
Permissions are unique and sorted. Mongo
transactions atomically update the principal and insert an immutable audit event
into `auth_permission_audit_events`. There is no audit update/delete API. Database
operator privileges and backup retention remain deployment responsibilities.

Provision the first administrator explicitly, after registering that user:

```sh
AUTH_CENTER_MONGO_URI='mongodb://127.0.0.1:27017/?replicaSet=rs0' \
AUTH_CENTER_MONGO_DATABASE='iwut_auth_center' \
AUTH_EMAIL_RECOVERY_READY=true AUTH_EMAIL_LOGIN_ENABLED=true \
go run ./cmd/auth-center bootstrap-platform-admin --auth-id '<existing-auth-id>'
```

The command uses Mongo configuration plus the two explicit email readiness flags;
it does not open listeners or load service/profile/signing configuration. The target
must already have an ACTIVE USER and verified email. JSON output contains `authId`,
`applied` and `eventId`. A single durable consumed marker permits same-subject replay
with `applied:false` and the original event ID, without restoring later-revoked
permissions. A different subject or incompatible/partial old initialization fails
closed. There is no migration or automatic startup grant.

Bootstrap grants the complete UC021 bundle: `auth.platform-admin.manage`,
`auth.reviewer.manage`, `auth.account.manage`, `auth.developer.manage`. It never grants
`app.profile.review` or `app.version.review`. Initialization writes
`auth_platform_admin_audit_events` with `actorType:BOOTSTRAP_COMMAND` and no fabricated
actor ID. Consumed bootstrap is not a recovery backdoor.

All changes join the same Mongo transaction fence as Session-to-JWS issuance.
Signing begun after a committed revoke sees the new permissions; existing JWSs
continue to their natural expiry. Unknown commit outcomes never return a success
result. Real Mongo tests cover rollback on audit failure, concurrent CAS, durable
bootstrap and issuance synchronization; production Wire tests exercise native
gRPC and generated HTTP clients plus real cryptographic identity issuance.
The UC010 E2E pulls and starts the published App Center image from
`APP_CENTER_IMAGE` (default:
`docker.cnb.cool/tokenteam/iwut-app-center:latest`) and checks both review handlers
against all four permission combinations. Pin `APP_CENTER_IMAGE` to an immutable
digest when reproducing a historical cross-service result. No existing account
receives profile-review permission automatically.

## Email registration and binding (UC011)

`AUTH_EMAIL_BINDING_ENABLED` defaults to `false`. Enabling it requires the complete
user endpoint runtime plus the v3/password gate, an independent email HMAC key and SMTP settings below.
Disabled HTTP routes are absent and the three native gRPC methods return
UNIMPLEMENTED. Startup validates configuration, CA certificates, database indexes
without sending probe mail.

| Variable | Meaning |
| --- | --- |
| `AUTH_EMAIL_BINDING_HMAC_KEY` | Required canonical standard Base64 of an independent random 32-byte key; must differ from email-login and password operation keys |
| `AUTH_SMTP_ADDR` | Required SMTP `host:port`, with a certificate valid for that host |
| `AUTH_SMTP_FROM` | Required single lowercase platform sender address |
| `AUTH_SMTP_TLS_MODE` | Required `implicit_tls` or `starttls`; verified TLS is mandatory |
| `AUTH_SMTP_USERNAME`, `AUTH_SMTP_PASSWORD` | Both supplied or both empty; authenticated SMTP negotiates advertised `PLAIN` or `LOGIN` after verified TLS |
| `AUTH_SMTP_CA_FILE` | Optional trusted CA PEM file; otherwise system roots |
| `AUTH_SMTP_TIMEOUT` | Positive duration, default `10s`, bounds the whole send |
| `AUTH_EMAIL_OWNER_HOURLY` | Positive sliding hourly account/public-key send quota, default `5` |
| `AUTH_EMAIL_ADDRESS_HOURLY` | Positive sliding hourly target-email send quota, default `5` |
| `AUTH_EMAIL_SOURCE_HOURLY` | Positive sliding hourly direct network peer send quota, default `20` |
| `AUTH_EMAIL_MAX_BUCKETS` | Positive total persistent quota bucket capacity, default `10000`; live buckets are never evicted |

Authenticated SMTP selects `PLAIN` when advertised and otherwise falls back to
advertised `LOGIN`; credentials are never sent before verified TLS is active. A
server offering only unsupported mechanisms such as `XOAUTH2` fails closed with
`EMAIL_DELIVERY_UNAVAILABLE`. OAuth-based SMTP authentication is not implemented.

V3 exposes the seven exact `auth_center.v3.email_account.EmailAccountService`
methods at `/v3/email-registrations`, `/v3/email-registrations:complete`,
`/v3/users/me/emails`, `/v3/users/me/email-verifications`,
`/v3/users/me/email-verifications:complete`, `/v3/users/me/login-email:switch`
and `/v3/users/me/emails:remove`. Anonymous registration rejects every supplied
Session carrier. Owner methods require exactly one current Session; other
identity carriers cannot substitute for it. Strict lowerCamelCase JSON rejects
unknown/duplicate/null/omitted fields and non-string int64 revisions. Native
Proto rejects duplicate/unknown fields before unmarshal loses them. Both use
16 KiB bounds, exact DIRECT dispatch and no-store responses.

Signup requires code, new-password policy and ten-field v3 device signature.
All new USER/password/directory/binding/key/Session/audit facts commit together;
SMTP only runs after confirmed Begin. Codes last ten minutes, permit five
failures and share the old persistent send budgets. Lost SMTP acknowledgments
retain the operation and quota; same requestId recovers metadata without sending
again. Signup never replays the Session token. Mutation retries can recover only
still-current non-secret state, not historical directory results.

Mongo stores the directory and bindings separately, with global address and
binding-ID uniqueness, no owner-unique binding index, and bounded 11-row integrity
reads. V3 proposals/mutations retain 24-hour idempotence records. Pending and
retained admission is shared with authentication operations under the same Auth
transaction fence; physical limits do not depend on timely TTL deletion. Cold
operation keys invalidate old proposals without changing verified email ownership.

## Current campus certification (UC031)

`AUTH_CAMPUS_CERTIFICATION_ENABLED` controls the retained three exact campus
verification/query routes. They require the v3/password runtime, use the ADD key
and budget, and derive membership from current verified exact WHUT addresses.
They can add a second campus binding; already-certified status is not a blocker.
The old campus code key is retired and ignored. No periodic revalidation or
student/enrollment/administrator authority is implied. Removing the last basis
removes certification immediately; old permanent facts never restore it.

OAuth `campus.whut` remains USERINFO_CAMPUS. Current client/grant/token/catalog,
account and channel gates control its minimal `iwut_campus` disclosure. It
contains no email, timestamp, authId or counter, and never enters the ID Token.
Consent, pairwise sub and application-owned benefits are not implicitly erased.

## Email login and device authorization (UC012)

`AUTH_EMAIL_LOGIN_ENABLED` defaults to `false`. When enabled it requires
`AUTH_USER_ENDPOINTS_ENABLED=true`, `AUTH_EMAIL_LOGIN_CODE_KEY` (canonical standard
Base64 of an independent random 32-byte key), and the SMTP settings documented
above. The login key must differ from the binding and password HMAC keys
when both email capabilities are enabled. Login can be enabled without binding
routes or the binding HMAC key. Disabled HTTP routes are absent; the two gRPC
methods return UNIMPLEMENTED.

The exact `auth_center.v1.email_login.EmailLoginService` methods are
`BeginEmailLogin` and `CompleteEmailLogin`, exposed at `POST /v1/email-logins`
(HTTP 200) and `POST /v1/email-logins/{operation_id}/completion` (HTTP 201).
Both reject any supplied `x-iwut-session`, including empty or valid tokens.
Gateway routing remains a separate delivery; the intended policy is DIRECT.

The client supplies its persistent device public key and email, then the emailed
code and the independent `iwut-email-login-v1` signature. The server keeps the
original primary-email role/revision and eligibility fixed for the operation,
rechecks them at commit, and atomically registers or reuses the device credential,
consumes the operation, applies Session LRU and inserts the Session and audit.
No USER or student association is created. Unknown/disabled targets receive the
same challenge/mail shape and cannot become eligible during that operation.

The resulting Session uses `EMAIL_CODE_AND_DEVICE`, a required device credential
reference and positive `emailBindingRevision` provenance. All Session consumers
support it, including revocation, binding and identity issuance. A login-role change
invalidates pending login operations but does not revoke authorized devices or
their Sessions; revoke the device credential to remove that access. Later UC007
automatic login uses the ordinary `DEVICE_CREDENTIAL` method. The same account-wide
10-Session limit covers both methods.

Login reuses UC011's authoritative binding directory, TLS SMTP, authentication
transaction fence, pending-operation capacity and shared email/source send quotas.
It uses separate purpose-bound request/code HMAC and key-change invalidation.
Repeated Begin requests never resend mail; completed login operations never replay
a Session token. On a lost completion response, retain the original private key
and recover through device login. A login HMAC key change closes pending login
operations without revoking already authorized devices or Sessions.

Validation includes the public login/registration/device vectors, real Mongo
transactions and concurrency, production Wire HTTP/gRPC with controlled TLS SMTP,
login-only startup, mixed-method LRU and Session consumers. All tests use isolated
resources and test addresses; this does not claim Gateway or mobile delivery.


## Developer self-enrollment (UC013)

`AUTH_DEVELOPER_APPLICATION_ENABLED=false` by default. Enable it only together
with `AUTH_USER_ENDPOINTS_ENABLED=true`; invalid combinations refuse startup.
The two exact `auth_center.v1.developer_application.DeveloperApplicationService`
methods are registered on both transports only when enabled:

- `ApplyForDeveloper`: `POST /v1/users/me/developer-application`, body
  `{"developerHandle":"Alice"}` (returns the canonical `alice`).
- `GetOwnDeveloperEligibility`: `GET /v1/users/me/developer-eligibility`, no body.

Both return HTTP 200 and require exactly one canonical `x-iwut-session`.
Both device and email/device Sessions work. They reject unknown JSON/Proto fields,
query parameters and alternative identity carriers; neither accepts a target ID.
Optional status/activation time retain presence: an ordinary user has no status;
a historical Developer without a verifiable activation record has no timestamp.
Eligibility omits `developerHandle` until a name is claimed. Apply always requires
a handle, including retries: old `{}` requests now fail `INVALID_DEVELOPER_HANDLE`.
All responses use `Cache-Control: no-store`.

First enrollment requires the current activated email and a recovery capability
composed from validated `AUTH_EMAIL_LOGIN_ENABLED=true` configuration and the
real TLS SMTP adapter. It additionally requires `AUTH_EMAIL_RECOVERY_READY=true`.
That flag defaults false and is an operator declaration that Gateway/client
email login and device recovery entry points have been delivered and verified.
Auth does not probe UI readiness or send a test email during enrollment. Keep the
flag false in production until public recovery delivery is complete. Email binding
routes need not be enabled to use an already activated email. Legitimately disabled
recovery produces an eligibility blocker; malformed configuration refuses startup.

The user chooses a public developer ID, `developerHandle`: 3–32 ASCII characters,
first character a letter, then letters, digits, `_` or `-`. Input is not trimmed;
only valid input is lowercased. The namespace is globally unique and each authId
can claim one name. There are no reserved words or implied official privileges;
`admin` and `official` are ordinary names. Names cannot be renamed, transferred,
released or recycled, including after account disable or Developer suspension.
Application UUIDs, ownership authId and JWS/UC002 claims remain unchanged. Public
`developerHandle/nameKey` lookup and routing are separate work.

Only explicit `null -> APPROVED` changes qualification. APPROVED with the same
canonical handle is idempotent, including when recovery is disabled. A different
handle returns `DEVELOPER_HANDLE_CHANGE_NOT_ALLOWED`; another account's name
returns `DEVELOPER_HANDLE_TAKEN` only after the caller's email/readiness gates.
PENDING conflicts and REJECTED/SUSPENDED cannot reapply. APPROVED legacy accounts
that have never claimed a handle can explicitly claim once through the same
command, requiring current email and recovery readiness. That operation preserves
activation time (including absence) and old activation/audit records, and writes
a separate `CLAIM_DEVELOPER_HANDLE` audit. Eligibility advertises this path via
canApply/blockers; it never claims a name or promises candidate availability.

Current Session, principal, binding and status are confirmed under the shared
authentication transaction fence. `auth_developer_handles` is the sole ownership
authority, with separate binary
unique indexes on authId and canonical developerHandle and no TTL. New activation
records and audit contain immutable handle evidence; missing, mismatched or
corrupt ownership fails closed and cannot become a legacy rename opportunity.
Indexed historical evidence also prevents another account from taking that name
when its authority row is missing.
`auth_developer_activations` has a unique authId. Audit uniqueness is now
`(subjectAuthId, action)`: startup creates that replacement index before dropping
the old single-subject unique index. This idempotent upgrade retains every event;
conflicting indexes/data stop startup. Name claim, status/updatedAt, activation
when applicable, and audit commit atomically. Audit stores handle, decision
revision, actor/subject, transition and UTC time; no email address or secrets.
Unknown commits return unavailable, permitting query/retry with the existing
Session. Permissions, permissionRevision, profile, association and Session lifetime
are preserved. UC002 and subsequent UC010 JWS read the current authoritative state.

The shared Apply/query limits use fixed minute windows and bounded memory:

| Environment | Default | Meaning |
| --- | --- | --- |
| `AUTH_DEVELOPER_GLOBAL_PER_MINUTE` | 600 | All admitted requests |
| `AUTH_DEVELOPER_SOURCE_PER_MINUTE` | 120 | Requests per socket peer address |
| `AUTH_DEVELOPER_ACCOUNT_PER_MINUTE` | 30 | Requests per authenticated authId |
| `AUTH_DEVELOPER_MAX_BUCKETS` | 4096 | Combined source/account bucket capacity |

Values must be integers in 1..1,000,000. Stale buckets are reclaimed when needed;
full capacity fails closed with 429 rather than evicting live buckets. Invalid
Session requests consume source/global admission, never arbitrary account buckets.
Database transaction retries debit the account only once. The conservative
`retryAfterSeconds=60` metadata also appears as HTTP `Retry-After`. Forwarding
headers are not trusted, so configure source limits for Gateway aggregate traffic.

`make test-mongo` includes production Wire HTTP/gRPC, real email binding/login
through local TLS capture, case-equivalent cross-account name races, same-account
name conflicts, legacy claim/index upgrade, corrupt ownership detection, atomic
Mongo concurrency/audit failures/unknown commits,
and same-Session UC010/UC002 verification. It pulls `APP_CENTER_IMAGE` (default:
`docker.cnb.cool/tokenteam/iwut-app-center:latest`), runs that image's migrations
and production server in a separate database, checks application creation with the
newly issued JWS, and verifies its quota and reviewer permission gates. Docker and
registry access are therefore required; override the image with a tag or digest
when needed. Gateway routes and mobile UX remain separate delivery.

## OAuth / OIDC (UC014–019)

Set `AUTH_CENTER_OAUTH_CONFIG_FILE` to an explicit JSON deployment manifest;
see `configs/oauth.example.json` and
[`oauth-runtime-implementation.md`](https://github.com/TokenTeam/iwut-docs/blob/main/auth-center/design-notes/oauth-runtime-implementation.md).
The manifest selects the persistent Mongo scope catalog, real App019 provider,
independent OIDC/delegation/service keys, official portal login URL and route policy.
Without it, existing endpoints retain their previous configuration.

OAuth scope entries use `Kind=PROTOCOL`, `RESOURCE`, or `USERINFO_PROFILE`.
A `USERINFO_PROFILE` entry must have an empty `Audience`, set `ProfileField` to an
existing UC005 field key, and use the exact name `profile.<ProfileField>`. Startup
cross-checks the complete profile catalog, derives and persists the field value type,
and rejects missing, duplicate or remapped fields. Operators must not configure
`ProfileValueType`; it is trusted only after derivation. Each enabled mapping becomes
an independently reviewed/consented scope and projects its current value under the
fixed UserInfo `iwut_profile` object. The example scope manifest deliberately contains
no production profile mapping; test fields are not a production collection list.

The backend provides authorization code consent, PUBLIC_PKCE and confidential
client exchange, opaque access/rotating refresh credentials, OIDC discovery/JWKS
and UserInfo, Session-authenticated grant management, and internal delegation
issuance. Standard OIDC HTTP endpoints use standard responses, not Proto envelopes.
Grant and token mutations share the authentication transaction fence.

Public OAuth defaults off. Enabling it requires explicit portal and Gateway
readiness; resource scopes additionally require resource-service readiness and
route/audience policy. Those flags do not verify deployment health. Official login
frontend, Traefik/Gateway OAuth forwarding and resource delegation verification
remain separate deliveries. Auth consumes App TEST, STABLE and GREY runtimes:
TEST requires its original active Tester episode; STABLE has no Tester requirement;
GREY requires current App cohort eligibility. There is no channel/major fallback.
Grant and credentials stay channel-bound; sector/sub stay Application-bound.
Existing TEST records need no migration. Explicit route `allowedChannels` may
contain any nonempty unique subset of the three channels; adding a channel changes
its policy digest and requires a matching Gateway deployment.

`make test-mongo` covers concurrent redemption/rotation, replay revocation,
catalog changes, grant epochs, transaction failures and production Wire endpoints.
The OAuth E2E starts the actual App Center, creates/reviews/publishes its fixtures
through APIs, and uses a standard OIDC client to verify discovery, JWKS and ID
tokens. Multi-channel coverage includes both client types, stable subjects,
independent grants, non-Tester STABLE/GREY access, cohort shrink/restoration,
publication clearing, stale codes and route-channel restrictions.
Its isolated App build uses a deterministic public DNS resolver through a
Go build overlay; it does not alter App source or system DNS.

## Application user storage (UC-AUTH-030)

`AUTH_APPLICATION_USER_STORAGE_ENABLED=false` by default. Setting it to `true`
requires both the OAuth runtime with `resourceScopesReady=true` and user endpoints;
startup also requires enabled, exactly bound `storage.read` and `storage.write`
catalog entries. It enables two Auth-owned, HTTP-only resource endpoints for third-party applications:

- `POST /v1/application-user-storage:batchGet`, requiring an opaque access token
  with the current `iwut-auth-center` audience and `storage.read`;
- `POST /v1/application-user-storage:mutate`, requiring the same audience and
  `storage.write`, plus whole-namespace `expectedRevision` CAS.

The same switch registers the user's generated HTTP/native gRPC
`DELETE /v1/users/me/application-user-storage/{application_id}` method. That method
uses the normal trusted Auth user identity, deletes all TEST/GREY/STABLE namespaces
for the caller and Application, and neither reads values nor revokes OAuth grants.

Namespaces are isolated by `(authId, applicationId, channel)`. Limits are fixed at
128 keys, 8 KiB per UTF-8 value, 64 KiB total key/value bytes, 64 unique operations
per request and a 16 KiB HTTP body. Third-party JSON rejects unknown or duplicate
names at every depth. Stale mutations return HTTP 409 with `minimumRevision`; the
caller must read again before retrying. Responses are `no-store`; PUBLIC browser
CORS uses the currently approved callback origin and CONFIDENTIAL clients do not
receive browser CORS.

Account closure includes this collection in its bounded cleanup plan. Application
closure creates a unique cleanup task in the same transaction as the permanent
tombstone and audit, then a lifecycle worker deletes at most 500 namespaces per
tick. Startup reconciles old tombstones before listeners start. These lifecycle
tasks run even while the public storage switch is off.

## Platform administrator management (UC-AUTH-021)

`AUTH_PLATFORM_ADMIN_ENDPOINTS_ENABLED` defaults to false; enabling it requires
`AUTH_USER_ENDPOINTS_ENABLED=true`. The independent generated service exposes:

- `POST /v1/platform-administrators:manage`: GRANT/REVOKE with `subjectAuthId`,
  required positive `expectedPermissionRevision` and a trimmed 1–1024-byte `reason`.
- `POST /v1/platform-administrators:get`: current eligibility by `subjectAuthId`.
- `POST /v1/platform-administrators:list`: granted members including disabled ones,
  `pageSize` default 20 (1–50), and exclusive lexical `afterAuthId` cursor.

Native gRPC exposes the matching three exact `PlatformAdministratorService` methods.
Gateway must use SESSION policy and the Auth audience, adding `/auth-center` externally.
Direct Session, service tokens, App-audience JWS and OAuth access tokens are rejected.
The service verifies the signed management claim and reads the current complete
administrator bundle before every read/write. HTTP uses strict ProtoJSON, no query,
16 KiB bodies and `Cache-Control: no-store`. Gateway route rollout remains separate.

Grants require a verified email and both `AUTH_EMAIL_RECOVERY_READY=true` and an
operationally configured `AUTH_EMAIL_LOGIN_ENABLED=true`. These conditions do not
block revocation or reads. The four permissions are an indivisible bundle; partial
stored bundles fail closed. Changes preserve reviewer permissions, Developer state
and Sessions. All changes share `permissionRevision` with UC004, so concurrent
commands compete on one revision. Unknown commits return unavailable; query current
state before retrying. Self-revocation returns success, then the old JWS loses access.

The global authentication transaction fence protects the last ACTIVE administrator,
including concurrent self-revocations. Disabled administrators cannot satisfy the
invariant. Account disabling and closing must reuse the same shared helper and fence.
Audit events are append-only in `auth_platform_admin_audit_events`; no audit edit/delete
endpoint exists. Existing signed identities may remain valid at offline consumers
until expiry, but Auth management handlers online-check current authority.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTH_PLATFORM_ADMIN_READ_PER_MINUTE` | 60 | Reads per authenticated actor |
| `AUTH_PLATFORM_ADMIN_WRITE_PER_MINUTE` | 10 | Writes per authenticated actor |
| `AUTH_PLATFORM_ADMIN_MAX_BUCKETS` | 4096 | Bounded combined read/write buckets |

The explicit first-deployment bootstrap above is performed during maintenance;
create and verify the user first, then stop listeners for provisioning. There is no
legacy bootstrap migration. To test a changed initialization format, explicitly
create a fresh disposable database; never delete production consumed markers.
Normal credential recovery uses email login. A separate audited offline break-glass
recovery procedure for loss of all administrator login methods is still a production
readiness dependency and is not implemented by this UC.

## Academic-year schedule management (UC-AUTH-029)

The Mongo-authoritative schedule is provisioned whenever user endpoints start, even
when its management API is disabled. It initially advances at September 1 00:00 in
Asia/Shanghai. Profile grade editing and scoped UserInfo disclosure use the same
schedule inside the shared authentication transaction; neither relies on a local
file or a cron write.

`AUTH_ACADEMIC_YEAR_POLICY_ENDPOINTS_ENABLED=false` by default. Enabling it requires
user endpoints and Auth-audience identity issuance, and registers:

- `GET /v1/academic-year-policy/schedule`, returning the current academic year,
  strictly future next rollover, observation time and configuration revision;
- `PUT /v1/academic-year-policy/schedule/next-rollover`, accepting a complete future
  Timestamp, positive expected revision and trimmed 1–1024-byte reason.

Both methods require the current complete platform-administrator bundle. Updates do
not change the current academic year immediately. The configured Instant becomes the
next boundary, and later boundaries recur by one Shanghai calendar year; February 29
normalizes to March 1 in the following non-leap year and remains March 1. Reads and
no-op updates do not advance the configuration revision or append audit records.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTH_ACADEMIC_YEAR_POLICY_READ_PER_MINUTE` | 60 | Reads per authenticated actor |
| `AUTH_ACADEMIC_YEAR_POLICY_WRITE_PER_MINUTE` | 10 | Writes per authenticated actor |
| `AUTH_ACADEMIC_YEAR_POLICY_MAX_BUCKETS` | 4096 | Bounded combined read/write buckets |

## Application operations permissions (UC-AUTH-027)

`AUTH_APPLICATION_OPERATIONS_PERMISSION_ENDPOINTS_ENABLED=false` by default.
Enabling it requires user endpoints and user identity issuance. Native gRPC and
strict HTTP/JSON expose:

- `PUT /v1/users/{subject_auth_id}/application-operation-permissions/{permission}`
  to grant or revoke exactly `app.application.suspend` or
  `app.application.restore` with a positive expected permission revision and a
  trimmed 1–1024-byte reason;
- `GET /v1/users/{subject_auth_id}/application-operation-permissions` to return
  both permissions in lexical order, their granted/effective state, the account
  status, shared revision and current grant blockers.

Gateway uses SESSION policy and an Auth-audience USER identity. The signed identity
must contain `auth.platform-admin.manage`; Auth then verifies the current complete
platform administrator bundle in the same Mongo transaction as every read or write.
The operation permissions never authorize their own management. They remain
independent from Reviewer permissions and the fixed platform administrator bundle.

Granting requires an ACTIVE target, verified email, and both
`AUTH_EMAIL_RECOVERY_READY=true` and the operational email-login runtime. Reads and
revocations accept ACTIVE or DISABLED users, and disabled grants remain stored but
ineffective. CLOSED and SYSTEM targets are unavailable. All mutations share
`permissionRevision`, `authenticationFence`, and `auth_permission_audit_events`
with UC004; stale concurrent changes conflict and audit insertion is atomic.

Only App-audience user identities project these permissions. They are not OAuth
scopes and Auth-audience identities do not contain them. Existing issued App
identities retain the configured short TTL window after revocation. The App Center
state transitions that consume these claims are a separate delivery.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTH_APPLICATION_OPERATIONS_PERMISSION_READ_PER_MINUTE` | 60 | Reads per authenticated actor |
| `AUTH_APPLICATION_OPERATIONS_PERMISSION_WRITE_PER_MINUTE` | 10 | Writes per authenticated actor |
| `AUTH_APPLICATION_OPERATIONS_PERMISSION_MAX_BUCKETS` | 4096 | Bounded read/write limiter state |

## User account disable and restore (UC022)

`AUTH_ACCOUNT_MANAGEMENT_ENDPOINTS_ENABLED=true` registers the native gRPC and
HTTP/JSON `AccountManagementService`. It requires the user endpoint runtime and
an initialized UC021 administrator. Exact HTTP routes are
`POST /v1/user-accounts:get-status` and `POST /v1/user-accounts:manage-status`;
both consume an Auth-audience USER JWS carrying `auth.account.manage` and the
current account generation. The current full administrator bundle is checked
again in the shared Mongo authentication transaction. Reasons remain in audit
storage; status queries do not disclose them.

`accountRevision` is a positive BSON int64 initialized to 1 by registration.
Every successful disable or restore increments it. Device/email login proofs,
email binding operations, Sessions and OAuth interaction/code/access/family
records bind that immutable generation. Disabling and restoring never rebinds
old materials, scans historical tokens or recreates a Session. Credentials and
verified email bindings remain available for a fresh login. Old-generation
Sessions do not occupy current LRU capacity. Missing or invalid revisions fail
closed: there is no implicit generation 1 upgrade for old test databases.

Auth audience USER JWS carry `account_revision` as a canonical positive decimal
string. Auth consumers verify it against current authoritative account state,
including the final profile-write CAS and reviewer/admin transaction. App JWS,
OIDC ID tokens and delegation JWS do not gain this claim; already-issued
short-lived downstream identities retain the documented TTL/leeway window.

Account status changes and immutable audit events commit together, preserving
independent permissions, Developer state and consent. Disabling the last ACTIVE
administrator is rejected under the same fence as administrator revocation.
Closed accounts cannot be restored. Turning off the management endpoints does
not turn off generation checks.

| Environment | Default | Purpose |
| --- | --- | --- |
| `AUTH_ACCOUNT_MANAGEMENT_ENDPOINTS_ENABLED` | false | Enable the two management methods |
| `AUTH_ACCOUNT_MANAGEMENT_READ_PER_MINUTE` | 60 | Reads per signed actor |
| `AUTH_ACCOUNT_MANAGEMENT_WRITE_PER_MINUTE` | 10 | Writes per signed actor |
| `AUTH_ACCOUNT_MANAGEMENT_MAX_BUCKETS` | 4096 | Bounded read/write limiter state |

## Developer suspension and restoration (UC-AUTH-023)

`AUTH_DEVELOPER_MANAGEMENT_ENDPOINTS_ENABLED=false` by default. Enabling it requires
user endpoints. Native gRPC `DeveloperManagementService` and strict HTTP/JSON expose
`POST /v1/developers:manage-status` and `POST /v1/developers:get-managed-status`.
Gateway uses SESSION with Auth audience; Auth accepts only a valid USER JWS with
`auth.developer.manage`, then online-checks account generation and the entire current
administrator bundle. Invalid account generations produce 401, revoked management
membership 403. Bodies have a 16 KiB cap, no query/unknown/duplicate fields, and
responses use `Cache-Control: no-store`.

Commands carry `subjectAuthId`, SUSPEND/RESTORE, required positive
`expectedDeveloperRevision` and a trimmed 1–1024-byte reason. The revision starts at
0 for ordinary users and becomes 1 on first UC013 activation; every successful
lifecycle transition increments it exactly once. Missing/wrong BSON types and
partial legacy state are rejected rather than migrated. Existing activation/handle
history is preserved. SUSPEND accepts only APPROVED; RESTORE only SUSPENDED and
requires a currently verified email, `AUTH_EMAIL_RECOVERY_READY=true`, and the
configured email-login runtime. WITHDRAWN, PENDING and REJECTED cannot be restored.
The target may have an ACTIVE or DISABLED account; qualification restoration does
not restore a disabled account.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTH_DEVELOPER_MANAGEMENT_READ_PER_MINUTE` | 60 | Read requests per authenticated actor |
| `AUTH_DEVELOPER_MANAGEMENT_WRITE_PER_MINUTE` | 10 | Mutations per authenticated actor |
| `AUTH_DEVELOPER_MANAGEMENT_MAX_BUCKETS` | 4096 | Bounded read/write bucket capacity |

The Mongo authentication transaction fence makes status, revision, lifecycle audit
and cancellation of pending owner exits atomic. `auth_developer_lifecycle_audit_events`
records distinct events without changing UC013's one-time activation audit.
`CancelPendingOwnerExitsTx` writes CANCELLED plus a durable pending notification in
`auth_account_owner_exit_operations`; UC024's coordinator delivers/retries it after
commit. App availability cannot block a governance transaction. Neither a committed
withdrawal nor a committed account closure can be cancelled by suspension.

Session, credential, email, accountRevision, ordinary user grants, independent
reviewer/administrator permissions and permanent handle ownership are preserved.
New App-audience JWSs carry the changed Developer status; Auth's UC002 directory
reports it immediately. App's existing APPROVED-only application/version/profile,
publication, tester-administration and OAuth-client owner commands consume these
claims. Offline App verifier consumers retain the documented prior-JWS TTL window;
App's current-owner checks apply only where its own UC defines them.

The real production-Wire/App test exercises CreateApplication under new SUSPENDED
claims, the old APPROVED JWS window, restored qualification and the preserved
ordinary profile/Session. It also reads UC002 and exercises restoration with the
actual email-login runtime disabled. Mongo OAuth tests show owner suspension blocks
UserInfo/refresh while retaining user grants and unconsumed refresh credentials;
restoration resumes eligible credentials without reviving separately revoked tokens.
No publication slot, catalog entry or application URL is removed by this UC.

UC025 can retire the original bootstrap audit after its 180-day retention only by
atomically recording `auditRetiredAt` on the durable consumed marker and deleting the
event, after verifying the original subject's legal minimal CLOSED tombstone. The
marker reader still validates any extant original event, and accepts absence only
with a non-future retention receipt and a valid closed subject. This preserves other
administrators' access after founder account cleanup without allowing arbitrary
missing/corrupt audit evidence to initialize or restore privileges.

### Developer withdrawal and owner-exit delivery

`AUTH_OWNER_EXIT_CONFIG_FILE` loads the shared owner-exit runtime independently of
OAuth. The JSON manifest accepts `appTarget`, `appServerName`, `appCaFile`,
`appPlaintextLoopback`, `serviceKeyId`, `serviceKeyFile` and `appServiceId` (default
`app-center`). The private key is a service-caller RSA signing key; it must not be
an identity/OIDC/delegation signing key. Plaintext is restricted to a literal
loopback address. Register the matching Auth public key with App permissions
`app.account-owner-exit.prepare`, `app.account-owner-exit.finish`, and
`app.account-owner-exit.read`. Auth's ACTIVE App caller must have
`auth.account-owner-exit.read`. App must enable its account-owner-exit provider.

`AUTH_DEVELOPER_WITHDRAWAL_ENABLED=true` exposes the four direct Session commands;
it requires the user endpoints and owner-exit manifest. Read/write quotas default
to 60/10 per account per minute, configurable through
`AUTH_DEVELOPER_WITHDRAWAL_READ_PER_MINUTE`,
`AUTH_DEVELOPER_WITHDRAWAL_WRITE_PER_MINUTE`, and
`AUTH_DEVELOPER_WITHDRAWAL_MAX_BUCKETS` (default 4096).

Keep the owner-exit manifest configured when disabling public withdrawal so the
Kratos-managed worker continues delivering permanent decisions and reconciling
App cleanup. Its retries are durable, bounded to 100 operations per batch, use a
5-second RPC deadline, and back off from 1 to 60 seconds with jitter. Never TTL
or manually discard `auth_account_owner_exit_operations`: their terminal
summaries are the authority used by App recovery after a restart.

### Account closure (UC025)

Both listeners use an explicit 15-second bounded request timeout so the shared
password executor (at most 2 seconds queueing), App coordination (5-second RPC
deadline) and final Auth transactions can complete. A caller's shorter deadline
still applies; this does not extend proof, Session or token lifetimes.

`AUTH_ACCOUNT_CLOSURE_ENABLED=true` enables the five dedicated HTTP/native gRPC
account-closure methods. It requires the configured password runtime, user endpoints, the independent owner-exit
manifest above, `AUTH_CLOSURE_DATA_POLICY_READY=true`, and
`AUTH_TERMINATION_LEDGER_DIR` pointing to an existing private (`0700`), absolute,
non-symlink directory. The application does not create a missing mount. The
readiness assertion means the operator has actually implemented the documented
30-day backup/log expiry, data inventory and disabled-user/no-key intake process;
local tests do not establish that operational readiness. Public closure is off by
default. No normal Session, JWS or OAuth carrier is accepted on these methods.

A fresh registered-device signature and the current password jointly authorize
the preview (`PrepareAccountClosure.current_password`, field 3). An omitted
password is rejected, not treated as a signature-only legacy request. ACTIVE and
DISABLED users can use this dedicated proof, but disabled users receive no normal
Session. Password/signature failures share the operation's five-attempt ceiling.
Password verification uses the process-wide bounded executor and persistent
quota; Prepare/Ready/Confirm recheck password/account versions and the credential
cutoff in the final Auth transaction. Confirm/Cancel use only
`x-iwut-closure-confirmation`; status uses only `x-iwut-closure-receipt`. Never log
these values or put them in a URL. Confirm irreversibly commits CLOSED and a
persistent cleanup task; the response remains TERMINATION_PENDING until the
independent ledger has durably acknowledged both the terminal fact and its
minimal permanent key/handle reservations. Cleanup completion additionally waits
for the real App receipt. The worker retries in bounded batches and reports
errors/24-hour overdue cleanup without reopening the account.

The ledger is outside the business database backup lifecycle and must itself be
backed up without rolling back on a Mongo restore. Before reopening traffic after
restoring Mongo, run `auth-center reconcile-account-closures` with only the Mongo
URI/database and ledger-directory variables. This offline command verifies and
replays terminal facts and permanent namespace reservations; it starts no
listeners and requires no App connection or signing keys. It reports that
cross-service cleanup remains pending. Start the normal runtime afterwards to
finish it. Missing/corrupt/conflicting ledger facts fail closed. A ledger snapshot
alone, without its corresponding termination fact, cannot terminate an account.
Production restore drills must verify the independent ledger is the latest copy.

Setting the public flag back to false preserves recovery, background cleanup,
Cancel and receipt-only Get when the ledger configuration remains. Removing the
runtime configuration while persisted closure state exists prevents startup.
Limits default to 30 reads/minute and 10 writes/minute with 4096 in-process
buckets (`AUTH_ACCOUNT_CLOSURE_READ_PER_MINUTE`,
`AUTH_ACCOUNT_CLOSURE_WRITE_PER_MINUTE`, `AUTH_ACCOUNT_CLOSURE_MAX_BUCKETS`). The
worker interval defaults to `1s` (`AUTH_ACCOUNT_CLOSURE_WORKER_INTERVAL`, range
`10ms`–`1m`). These settings do not change proof/token expiry or grant another
login state. Gateway route wiring, client preview/confirmation UI and deployment
readiness remain separate delivery work.

### Same-account Session management (UC020)

`AUTH_SESSION_MANAGEMENT_ENABLED=true` enables `ListOwnSessions` and
`RevokeOwnSessions` through native gRPC and POST `/v1/users/me/sessions:list`
and `/v1/users/me/sessions:revoke`. The flag defaults to false and requires user
endpoints. Both accept only one canonical `x-iwut-session` header. Gateway DIRECT
route wiring and client session-list UI remain separate delivery work.

Listing does not refresh Session expiry or last-used timestamps. Results belong
to the caller's `authId`, independently of student association. Each page processes
at most 200 candidates; follow `nextCursor` even when the returned page is empty.
The cursor can name a filtered candidate. Batch revocation accepts 1–50 explicit
Session IDs, excludes the current Session, and never revokes device credentials
or OAuth tokens. Revoked devices can authenticate again with a valid credential.

The shared per-minute defaults are 600 globally, 120 per socket source, and 30 per
authenticated account, configured by `AUTH_SESSION_MANAGEMENT_GLOBAL_PER_MINUTE`,
`AUTH_SESSION_MANAGEMENT_SOURCE_PER_MINUTE`, and
`AUTH_SESSION_MANAGEMENT_ACCOUNT_PER_MINUTE`. Source and account entries share
`AUTH_SESSION_MANAGEMENT_MAX_BUCKETS` (default 4096). All limits are positive
integers at most 1,000,000. Forwarded headers do not establish source identity.
