package domain

import (
	"errors"
	"time"
)

var (
	ErrOverdue     = errors.New("ACCOUNT_CLOSURE_CLEANUP_OVERDUE")
	ErrInvalid     = errors.New("ACCOUNT_CLOSURE_INVALID_REQUEST")
	ErrProof       = errors.New("ACCOUNT_CLOSURE_PROOF_INVALID")
	ErrToken       = errors.New("ACCOUNT_CLOSURE_TOKEN_INVALID")
	ErrConflict    = errors.New("ACCOUNT_CLOSURE_CONFLICT")
	ErrUnavailable = errors.New("ACCOUNT_CLOSURE_UNAVAILABLE")
	ErrRate        = errors.New("ACCOUNT_CLOSURE_RATE_LIMITED")
)

const (
	Preparing          = "PREPARING"
	Ready              = "READY"
	Cancelled          = "CANCELLED"
	TerminationPending = "TERMINATION_PENDING"
	Terminated         = "TERMINATED"
	CleanupComplete    = "CLEANUP_COMPLETE"
	AdminBlocker       = "ADMIN_HANDOVER_REQUIRED"
	DeveloperBlocker   = "DEVELOPER_WITHDRAWAL_REQUIRED"
	LifecycleBlocker   = "LIFECYCLE_OPERATION_PENDING"
)

type BeginInput struct {
	RequestID, CredentialID string
	PublicKeyFingerprint    []byte
}
type Challenge struct {
	OperationID                             string
	Challenge, SigningPayload               []byte
	ExpiresAt                               time.Time
	ServiceID, ApplicationID, PolicyVersion string
}
type Preview struct {
	AuthID, DeveloperHandle, PolicyVersion  string
	Irreversible                            bool
	DataToDelete, PermanentRetention        []string
	ExpiresAt                               time.Time
	AuditRetentionDays, BackupRetentionDays int32
}
type Preparation struct {
	OperationID, Outcome, Blocker   string
	Preview                         *Preview
	ConfirmationToken, ReceiptToken string
}
type Status struct {
	State, CleanupProgress               string
	TerminatedAt, BackupExpiryUpperBound *time.Time
}

// Operation secrets are digests only. Device material is retained only until
// terminal cleanup; the independent termination record has its own minimal type.
type Operation struct {
	OperationID          string
	RequestID            string
	LocatorKind          string
	LocatorValue         []byte
	Challenge            []byte
	ServiceID            string
	ApplicationID        string
	PolicyVersion        string
	CreatedAt            time.Time
	ExpiresAt            time.Time
	RetainUntil          time.Time
	AuthID               string
	CredentialID         string
	PublicKey            []byte
	AccountRevision      int64
	DeveloperRevision    int64
	PermissionRevision   int64
	MutationDigest       []byte
	Acceptable           bool
	FailedAttempts       int
	State                string
	Blocker              string
	DeveloperHandle      string
	ConfirmationDigest   []byte
	ReceiptDigest        []byte
	TerminatedAt         *time.Time
	LedgerConfirmed      bool
	LocalCleanupComplete bool
}

func (o Operation) Proof() Proof {
	return Proof{ServiceID: o.ServiceID, ApplicationID: o.ApplicationID, OperationID: o.OperationID, Challenge: o.Challenge, ExpiresAt: o.ExpiresAt, LocatorKind: o.LocatorKind, LocatorValue: o.LocatorValue, PolicyVersion: o.PolicyVersion}
}
func (o Operation) Termination() Termination {
	t := Termination{AuthID: o.AuthID, AccountRevision: o.AccountRevision + 1, OperationID: o.OperationID}
	if o.TerminatedAt != nil {
		t.TerminatedAt = *o.TerminatedAt
	}
	return t
}
