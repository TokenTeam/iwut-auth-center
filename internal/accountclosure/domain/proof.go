package domain

import "time"

const PolicyVersion = "account-closure-v1"
const ProofPurpose = "PREPARE_ACCOUNT_CLOSURE"

type Proof struct {
	ServiceID, ApplicationID, OperationID string
	Challenge                             []byte
	ExpiresAt                             time.Time
	LocatorKind                           string
	LocatorValue                          []byte
	PolicyVersion                         string
}

type TokenPurpose string

const (
	ConfirmationToken TokenPurpose = "confirmation"
	ReceiptToken      TokenPurpose = "receipt"
)
