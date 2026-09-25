package domain

import "time"

const (
	ProtocolVersion     = "iwut-device-v1"
	ApplicationID       = "iwut-client"
	Register            = "REGISTER"
	Login               = "LOGIN"
	Pending             = "PENDING"
	Completed           = "COMPLETED"
	Closed              = "CLOSED"
	CredentialIDLocator = "CREDENTIAL_ID"
	FingerprintLocator  = "PUBLIC_KEY_FINGERPRINT"
)

// Operation contains only immutable proof context and controlled association ciphertext.
// SigningPayload, association plaintext/digest and session tokens MUST NOT be persisted.
type Operation struct {
	OperationID, Purpose, ProtocolVersion, ServiceID, ApplicationID string
	Challenge                                                       []byte
	ExpiresAt, CreatedAt                                            time.Time
	LocatorKind                                                     string
	LocatorValue                                                    []byte
	CredentialID, AuthID                                            string
	PublicKey                                                       []byte
	Acceptable                                                      bool
	Status                                                          string
	FailedAttempts                                                  int
	CompletedAuthID, CompletedCredentialID, CompletedSessionID      string
	SchemeVersion, KeyVersion                                       string
	LookupKey, Nonce, Ciphertext                                    []byte
}

type Credential struct {
	CredentialID, AuthID, ProtocolVersion string
	PublicKey, Fingerprint                []byte
	CreatedAt                             time.Time
	RevokedAt                             *time.Time
}

type Session struct {
	SessionID, AuthID, AuthenticationMethod, CredentialID string
	TokenDigest                                           []byte
	EmailBindingRevision                                  int64
	AuthenticatedAt, CreatedAt, LastUsedAt, ExpiresAt     time.Time
	RevokedAt                                             *time.Time
}

type Challenge struct {
	OperationID, ProtocolVersion string
	Challenge, SigningPayload    []byte
	ExpiresAt                    time.Time
}

// Established is transient. SessionToken is only returned after confirmed commit.
type Established struct {
	AuthID, CredentialID, SessionID, SessionToken string
	ExpiresAt                                     time.Time
}

type Locator struct {
	Kind  string
	Value []byte
}
