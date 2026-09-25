# iWUT Auth Center

This orphan-branch implementation bootstraps Auth Center from the authoritative
design in `../../docs/auth-center/`. It exposes the full scope catalog snapshot
the current Developer status projection and Auth-owned SYSTEM principals to
authorized internal services through native gRPC.

The current catalog remains deliberately hard-coded. Developer and SYSTEM
principals are read from Auth-owned MongoDB collection `auth_principals`.
Internal business RPCs use caller-signed service JWS and a fixed permission
allowlist. The optional UC005–009 user endpoints add profile editing, app-managed
device registration/login, Session revocation and credential revocation over both
HTTP/JSON and native gRPC. Their
authentication is selected by exact full method, following
`../../docs/platform/contracts/auth-device-session-v1.md`.

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

## Temporary implementation boundary

- The scope catalog remains hard-coded. The profile field catalog is a separate
  validated deployment file; a production field list still requires a product decision.
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

Set `AUTH_USER_ENDPOINTS_ENABLED=true` to register UC005–009. It defaults to false
for deployments using only the existing internal methods. Enabling it requires
all configuration below; missing or invalid values fail startup. MongoDB must be
a replica set (a single member is sufficient) or a transaction-capable cluster.
Startup probes a real transaction before serving requests.

| Variable | Required when enabled | Meaning |
| --- | --- | --- |
| `AUTH_AUTHENTICATION_SERVICE_ID` | yes | Stable deployment identity, for example `iwut-auth-center:prod`; clients must use the same value |
| `AUTH_SESSION_TTL` | yes | Positive whole-millisecond Go duration; `720h` is an example, not a default |
| `AUTH_ASSOC_KEY_VERSION` | yes | Current association encryption/lookup key version |
| `AUTH_ASSOC_ENCRYPT_KEY` | yes | Canonical standard Base64 of an independent random 32-byte AES key |
| `AUTH_ASSOC_LOOKUP_KEY` | yes | Canonical standard Base64 of a separate random 32-byte HMAC key |
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
`RevokeCurrentSession` accepts only its `x-iwut-session` token and succeeds
idempotently even when that correctly formatted token is expired or unknown.
`RevokeOwnCredential` requires a currently valid Session in that header.
Gateway routes, old-device authorization and mobile key storage/UI remain
separate deliveries. Email recovery through a new device is implemented by UC012 below. These are app-managed device
keys, not WebAuthn Passkeys.

## HTTP/JSON interface

The Wire composition root starts both Kratos servers and reuses the same services
and authentication dispatch. Set `AUTH_CENTER_HTTP_ADDR` (default `:8000`) and
`AUTH_CENTER_GRPC_ADDR` (default `:9000`). `AUTH_USER_ENDPOINTS_ENABLED=false`
leaves the HTTP user routes unregistered. Internal scope, developer, SYSTEM and
Session-to-JWS APIs remain native gRPC only.

The authoritative route mapping is [Auth API routing](../../docs/platform/contracts/auth-center-api-routing.md).
Proto HTTP annotations use service-local `/v1/...` paths, like App Center;
`/auth-center` belongs to Gateway prefix stripping and is not accepted by Auth.
Gateway routing is a separate delivery.

| Method | Service-local path | RPC |
| --- | --- | --- |
| POST | `/v1/registrations` | BeginUserRegistration |
| POST | `/v1/registrations/{operation_id}/completion` | CompleteUserRegistration |
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
All responses carry `Cache-Control: no-store`; registration/login completion
return 201, other successes return 200 (revocation returns `{}`). Error JSON
preserves the same stable reason as gRPC, with UC-specific 400/401/403/404/409/
413/429/503 status mapping. Parser errors never echo raw submitted values.

`cmd/auth-center/http_e2e_test.go` runs against the real Wire process and MongoDB,
covering the nine routes, generated HTTP clients, strict JSON, Session headers,
profile CAS, revocation retries, and isolation of internal methods. The existing
gRPC provider tests exercise the same running composition root.

## Cold key rotation and storage

Stop the old process and drain requests. Inject the new current key group and
exactly one previous group using `AUTH_ASSOC_PREVIOUS_KEY_VERSION`,
`AUTH_ASSOC_PREVIOUS_ENCRYPT_KEY`, and `AUTH_ASSOC_PREVIOUS_LOOKUP_KEY`.
All encryption and lookup keys must be distinct. The new process closes pending
registration operations, migrates groups in batches of at most 500, verifies all
resulting ciphertext/lookup pairs and counts, then starts listening. It preserves
association IDs and memberships. The startup gate has a 10-minute deadline.
Failure exits before listening; restart with the same groups to retry idempotently.
After success, future starts can omit all previous-key variables. Keep the keys
needed to decrypt retained backups under the backup restoration policy.
A production-size maintenance-window measurement is still required on the real
transaction-enabled MongoDB deployment; local tests do not establish that budget.

Collections are separate: `auth_principals` (embedded profile), `auth_credentials`,
`auth_sessions`, `auth_authentication_operations`, `auth_student_associations`,
`auth_student_association_members`, and `auth_runtime`. Unique indexes guard IDs,
credential fingerprints, Session token digests and keyed association lookups.
The current single-process implementation serializes authentication transactions
with the `auth_runtime/authentication` fence before touching operation, principal,
credential and Session state. This favors correctness over throughput; future
principal disable and credential mutation must join the same transaction protocol.
Profile optimistic updates preserve the other principal fields.

Session tokens, raw association tokens, student numbers and registration signing
payloads are not persisted. Association tokens use authenticated encryption;
lookup HMAC and encryption use distinct keys. Completed/closed registration
snapshots clear encrypted token material. Revoked Sessions and credential rows
are conservatively retained: no TTL deletion currently releases audit markers or
public-key ownership. Physical retention/cleanup is a later maintenance task.

`cmd/auth-center/user_endpoints_e2e_test.go` exercises the production Wire root,
real gRPC generated clients and MongoDB for registration → profile → login →
Session/credential revocation → cold rotation → association reuse. Run
`./scripts/test-mongo-integration.sh -race` for all database and provider tests.
The script starts an isolated single-member replica set with fault injection
enabled only in that test container and removes it on exit.

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

The Auth audience receives only `auth.reviewer.manage`; the App audience receives
only `app.version.review` plus a valid existing Developer status, when present.
These are intersections with current authoritative permissions, never grants.
Ordinary users get `permissions: []` and no Developer claim. Session expiry bounds
`exp`, so issuing never extends a Session. There is no Redis requirement.

`cmd/auth-center/identity_issuance_e2e_test.go` covers real registration, production
Wire/RSA service identity, native gRPC/Mongo issuance, real target profile
verification, audience authorization and current capabilities/revocation. The
Mongo integration suite additionally injects signer and unknown-commit failures
and exercises concurrent capability/revocation writes. Tests log bounded local
RSA and RPC/Mongo measurements; they are not production capacity estimates.
Gateway routing and UC004 permission-management commands remain separate work.

## Reviewer permission management (UC-AUTH-004)

User endpoint runtime also registers `ReviewerPermissionService` in both native
gRPC and HTTP. Gateway uses SESSION policy with `iwut-auth-center` audience:

- `GET /v1/users/{subject_auth_id}/reviewer-permission` reads the current state.
- `PUT /v1/users/{subject_auth_id}/reviewer-permission` accepts `action` (`1` grant,
  `2` revoke), positive `expectedRevision`, and a reason (trimmed, 1–1024 UTF-8
  bytes). The path owns the subject ID. Both return `subjectAuthId`, `reviewer`,
  and `permissionRevision` (ProtoJSON decimal string).

A verified user JWS must contain `auth.reviewer.manage`; both operations also
confirm the actor's current ACTIVE USER state and current grant in Mongo. Only
ACTIVE USER subjects are eligible. Repeated actions and stale revisions return
409; query current state after an uncertain response before deciding to retry.
Permissions preserve unrelated capabilities and are unique and sorted. Mongo
transactions atomically update the principal and insert an immutable audit event
into `auth_permission_audit_events`. There is no audit update/delete API. Database
operator privileges and backup retention remain deployment responsibilities.

Provision the first administrator explicitly, after registering that user:

```sh
AUTH_CENTER_MONGO_URI='mongodb://127.0.0.1:27017/?replicaSet=rs0' \
AUTH_CENTER_MONGO_DATABASE='iwut_auth_center' \
go run ./cmd/auth-center bootstrap-platform-admin --auth-id '<existing-auth-id>'
```

The command requires only Mongo configuration and does not open listeners or load
service/profile/signing configuration. JSON output contains `authId` and `applied`.
A durable global marker permits a same-subject replay with `applied:false`, without
restoring a later-revoked grant; another subject is rejected. Bootstrap grants only
`auth.reviewer.manage`, never reviewer authority. Audit attribution uses
`actorType:BOOTSTRAP_COMMAND` with no fabricated `actorAuthId`; ordinary management
uses `actorType:USER` and the verified administrator ID. No generic administrator
management API is provided here.

All changes join the same Mongo transaction fence as Session-to-JWS issuance.
Signing begun after a committed revoke sees the new permissions; existing JWSs
continue to their natural expiry. Unknown commit outcomes never return a success
result. Real Mongo tests cover rollback on audit failure, concurrent CAS, durable
bootstrap and issuance synchronization; production Wire tests exercise native
gRPC and HTTP plus real cryptographic identity issuance.

## Email registration and binding (UC011)

`AUTH_EMAIL_BINDING_ENABLED` defaults to `false`. Enabling it requires the complete
user endpoint runtime plus an independent email HMAC key and SMTP settings below.
Disabled HTTP routes are absent and the three native gRPC methods return
UNIMPLEMENTED. Startup validates configuration, CA certificates, database indexes
and migration state without sending probe mail.

| Variable | Meaning |
| --- | --- |
| `AUTH_EMAIL_BINDING_HMAC_KEY` | Required canonical standard Base64 of an independent random 32-byte key; must differ from current/previous association keys |
| `AUTH_SMTP_ADDR` | Required SMTP `host:port`, with a certificate valid for that host |
| `AUTH_SMTP_FROM` | Required single lowercase platform sender address |
| `AUTH_SMTP_TLS_MODE` | Required `implicit_tls` or `starttls`; verified TLS is mandatory |
| `AUTH_SMTP_USERNAME`, `AUTH_SMTP_PASSWORD` | Both supplied or both empty |
| `AUTH_SMTP_CA_FILE` | Optional trusted CA PEM file; otherwise system roots |
| `AUTH_SMTP_TIMEOUT` | Positive duration, default `10s`, bounds the whole send |
| `AUTH_EMAIL_OWNER_HOURLY` | Positive sliding hourly account/public-key send quota, default `5` |
| `AUTH_EMAIL_ADDRESS_HOURLY` | Positive sliding hourly target-email send quota, default `5` |
| `AUTH_EMAIL_SOURCE_HOURLY` | Positive sliding hourly direct network peer send quota, default `20` |
| `AUTH_EMAIL_MAX_BUCKETS` | Positive total persistent quota bucket capacity, default `10000`; live buckets are never evicted |

The three exact `auth_center.v1.email_binding.EmailBindingService` methods are
`BeginSetEmail`, `CompleteSetEmail` and `GetOwnEmailBinding`, mapped respectively to
`POST /v1/email-bindings`, `POST /v1/email-bindings/{operation_id}/completion` and
`GET /v1/users/me/email-binding`. Both completion modes return HTTP 200. Gateway
uses DIRECT forwarding with the `/auth-center` prefix stripped; Gateway and
mobile implementation are separate work packages.

Absent `x-iwut-session` selects email registration; a valid token selects binding
to the current account. Empty, malformed, duplicate, expired or revoked tokens
are rejected. The operation's mode cannot change. Registration requires the
existing `iwut-device-v1` public-key proposal and student association declaration,
then both the email code and an independent `iwut-email-registration-v1` device
proof. Begin creates no account. Complete creates USER, device, association,
first Session and revision-1 email binding in one Mongo transaction. BIND requires
an explicit nonnegative `expectedRevision` (including initial zero) and a current
same-account Session at completion. Replacing an email preserves the old binding
until the new address is verified and committed. Query always requires Session.

Codes are eight ASCII digits (including leading zeros), expire at ten minutes,
and share a five-failure limit with device proof failures. Each owner/public key
and target email has a fixed 60-second resend cooldown. Send quotas are persistent
sliding 60-minute windows. General authentication request limits also apply.
The peer address is taken from the transport connection, never caller-supplied
forwarding headers. Size is bounded at 16 KiB; JSON and protobuf reject unknown
and ambiguous fields. Responses carry `Cache-Control: no-store`.

`requestId` deduplication lasts at least 24 hours and never sends the same operation
again. A delivery rejection, timeout or lost SMTP acknowledgement returns
EMAIL_DELIVERY_UNAVAILABLE while preserving the operation and consumed quota.
Retry the same request ID to recover operation metadata; resend explicitly with
a new ID after cooldown. REGISTER completion never returns its Session token on
replay: keep the original device private key and use ordinary device login if
the first completion response is lost or the commit outcome is unknown. BIND
completion can recover its historical result with the original code and a valid
same-account Session; query returns the current binding.

Mongo uses `auth_email_bindings`, `auth_email_operations`, `auth_email_quotas` and
`auth_email_audit`, plus the shared authentication operation collection for
REGISTER_WITH_EMAIL encrypted association snapshots. Unique indexes guard owner
and activated email. All activation/revocation checks and quota debits use the
shared authentication transaction fence. TTL removes retained operation history
and expired quota buckets; expiry/state checks never rely on TTL timing. A cold
HMAC key change closes old pending operations and clears association ciphertext,
without changing activated bindings or releasing retained request IDs. Completed
registration markers survive the key change. Association-key rotation includes
both ordinary and email registration snapshots.

SMTP sending occurs once, after a confirmed Begin transaction, and uses fixed
purpose templates. No plaintext code, student association token, signing payload
or Session secret is persisted. Audit contains only account/operation IDs,
revision, timestamp and result. SMTP failures never return server response text.
Tests use only loopback TLS SMTP capture and `.test` addresses, never real users.
Public vectors, real Mongo rollback/concurrency/rotation/quota tests and production
Wire HTTP/gRPC tests cover the implementation. UC012 email login is described
below; UC013 Developer enrollment is described next. Public client delivery remains separate.


## Email login and device authorization (UC012)

`AUTH_EMAIL_LOGIN_ENABLED` defaults to `false`. When enabled it requires
`AUTH_USER_ENDPOINTS_ENABLED=true`, `AUTH_EMAIL_LOGIN_CODE_KEY` (canonical standard
Base64 of an independent random 32-byte key), and the SMTP settings documented
above. The login key must differ from association keys and the binding HMAC key
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
original email ownership/revision and eligibility fixed for the operation,
rechecks them at commit, and atomically registers or reuses the device credential,
consumes the operation, applies Session LRU and inserts the Session and audit.
No USER or student association is created. Unknown/disabled targets receive the
same challenge/mail shape and cannot become eligible during that operation.

The resulting Session uses `EMAIL_CODE_AND_DEVICE`, a required device credential
reference and positive `emailBindingRevision` provenance. All Session consumers
support it, including revocation, binding and identity issuance. An email change
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

- `ApplyForDeveloper`: `POST /v1/users/me/developer-application`, body `{}`.
- `GetOwnDeveloperEligibility`: `GET /v1/users/me/developer-eligibility`, no body.

Both return HTTP 200 and require exactly one canonical `x-iwut-session`.
Both device and email/device Sessions work. They reject unknown JSON/Proto fields,
query parameters and alternative identity carriers; neither accepts a target ID.
Optional status/activation time retain presence: an ordinary user has no status;
a historical Developer without a verifiable activation record has no timestamp.
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

Only explicit `null -> APPROVED` changes state. Repeated APPROVED is idempotent
(including when recovery is disabled), PENDING conflicts, and REJECTED/SUSPENDED
cannot reapply here. Current Session, principal, binding and status are confirmed
under the shared authentication transaction fence. `auth_developer_activations`
has a unique authId; `auth_developer_application_audit` has a unique subjectAuthId.
Both records and the principal status commit atomically. Audit stores decision
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
through local TLS capture, atomic Mongo concurrency/audit failures/unknown commits,
and same-Session UC010/UC002 verification. When the sibling App Center checkout is
available, it also builds and starts its actual production binary and migrations
in a separate database, checks application creation with the newly issued JWS,
and verifies its quota and reviewer permission gates. Set `APP_CENTER_SOURCE_DIR`
to override the sibling path; that subtest explicitly skips if no checkout exists.
No App source is modified. Gateway routes and mobile UX remain separate delivery.
