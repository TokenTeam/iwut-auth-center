# iWUT Auth Center

This orphan-branch implementation bootstraps Auth Center from the authoritative
design in `../../docs/auth-center/`. It exposes the full scope catalog snapshot
the current Developer status projection and Auth-owned SYSTEM principals to
authorized internal services through native gRPC.

The current catalog remains deliberately hard-coded. Developer and SYSTEM
principals are read from Auth-owned MongoDB collection `auth_principals`.
Internal business RPCs use caller-signed service JWS and a fixed permission
allowlist. The optional UC005–009 user endpoints add profile editing, app-managed
device registration/login, Session revocation and credential revocation. Their
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

`make run` starts a native gRPC listener on `:9000` by default. There is no HTTP
route and no gRPC-Web exposure in Auth Center; an eventual Gateway/Traefik edge
owns external protocol mapping.

## Environment

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
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
- Private keys are never accepted by Auth. Caller public keys, permissions and
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
Session-to-JWS issuance, Gateway routes, email recovery, device migration and
mobile key storage/UI remain separate deliveries. These are app-managed device
keys, not WebAuthn Passkeys.

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
