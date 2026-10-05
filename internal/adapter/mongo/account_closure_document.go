package mongo

import "time"

type closureOperationDocument struct {
	OperationID          string     `bson:"operationId"`
	RequestID            string     `bson:"requestId"`
	LocatorKind          string     `bson:"locatorKind"`
	LocatorValue         []byte     `bson:"locatorValue"`
	Challenge            []byte     `bson:"challenge"`
	ServiceID            string     `bson:"serviceId"`
	ApplicationID        string     `bson:"applicationId"`
	PolicyVersion        string     `bson:"policyVersion"`
	CreatedAt            time.Time  `bson:"createdAt"`
	ExpiresAt            time.Time  `bson:"expiresAt"`
	RetainUntil          time.Time  `bson:"retainUntil"`
	AuthID               string     `bson:"authId,omitempty"`
	CredentialID         string     `bson:"credentialId,omitempty"`
	PublicKey            []byte     `bson:"publicKey,omitempty"`
	AccountRevision      int64      `bson:"accountRevision"`
	DeveloperRevision    int64      `bson:"developerRevision"`
	PermissionRevision   int64      `bson:"permissionRevision"`
	MutationDigest       []byte     `bson:"mutationDigest,omitempty"`
	Acceptable           bool       `bson:"acceptable"`
	FailedAttempts       int        `bson:"failedAttempts"`
	State                string     `bson:"state"`
	Blocker              string     `bson:"blocker,omitempty"`
	DeveloperHandle      string     `bson:"developerHandle,omitempty"`
	ConfirmationDigest   []byte     `bson:"confirmationDigest,omitempty"`
	ReceiptDigest        []byte     `bson:"receiptDigest,omitempty"`
	TerminatedAt         *time.Time `bson:"terminatedAt,omitempty"`
	LedgerConfirmed      bool       `bson:"ledgerConfirmed"`
	LocalCleanupComplete bool       `bson:"localCleanupComplete"`
}
