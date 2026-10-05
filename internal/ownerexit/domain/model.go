package domain

import (
	"errors"
	"github.com/google/uuid"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Pending    = "PENDING"
	Committed  = "COMMITTED"
	Cancelled  = "CANCELLED"
	Withdrawal = "DEVELOPER_WITHDRAWAL"
	Closure    = "ACCOUNT_CLOSURE"
)

var (
	ErrInvalid     = errors.New("OWNER_EXIT_INVALID_REQUEST")
	ErrConflict    = errors.New("OWNER_EXIT_CONFLICT")
	ErrNotFound    = errors.New("OWNER_EXIT_NOT_FOUND")
	ErrUnavailable = errors.New("OWNER_EXIT_UNAVAILABLE")
)

// Operation is the durable cross-service decision. Proofs and closure secrets
// belong to their own collections; terminal summaries are never TTL-deleted.
type Operation struct {
	OperationID         string     `bson:"operationId"`
	AuthID              string     `bson:"authId"`
	Purpose             string     `bson:"purpose"`
	Decision            string     `bson:"decision"`
	ReceiptID           string     `bson:"receiptId,omitempty"`
	RequestID           string     `bson:"requestId,omitempty"`
	SessionID           string     `bson:"sessionId,omitempty"`
	AccountRevision     int64      `bson:"accountRevision"`
	DeveloperRevision   int64      `bson:"developerRevision"`
	PermissionRevision  int64      `bson:"permissionRevision"`
	CreatedAt           time.Time  `bson:"createdAt"`
	ExpiresAt           time.Time  `bson:"expiresAt"`
	DecidedAt           *time.Time `bson:"decidedAt,omitempty"`
	CancellationReason  string     `bson:"cancellationReason,omitempty"`
	Blocker             string     `bson:"blocker,omitempty"`
	NotificationPending bool       `bson:"notificationPending"`
	NextAttemptAt       time.Time  `bson:"nextAttemptAt"`
	Attempts            int64      `bson:"attempts"`
	AppAcknowledged     bool       `bson:"appAcknowledged"`
	AppCleanupState     string     `bson:"appCleanupState,omitempty"`
}

func ValidAuthID(s string) bool {
	return s != "" && len(s) <= 200 && utf8.ValidString(s) && strings.TrimSpace(s) == s
}
func ValidOperationID(s string) bool {
	id, e := uuid.Parse(s)
	return e == nil && id.Version() == 4 && id.String() == s
}
func ValidReceiptID(s string) bool {
	id, e := uuid.Parse(s)
	return e == nil && id.Version() == 7 && id.String() == s
}
func (o Operation) Valid() bool {
	return ValidOperationID(o.OperationID) && ValidAuthID(o.AuthID) && (o.Purpose == Withdrawal || o.Purpose == Closure) && (o.Decision == Pending || o.Decision == Committed || o.Decision == Cancelled) && o.AccountRevision > 0 && o.DeveloperRevision >= 0 && o.PermissionRevision > 0 && !o.CreatedAt.IsZero() && o.ExpiresAt.After(o.CreatedAt) && o.ExpiresAt.Sub(o.CreatedAt) <= 10*time.Minute && (o.ReceiptID == "" || ValidReceiptID(o.ReceiptID)) && (o.Decision != Committed || o.ReceiptID != "") && o.Attempts >= 0 && (o.Decision == Pending && o.DecidedAt == nil || o.Decision != Pending && o.DecidedAt != nil)
}

type Preparation struct{ ReceiptID, Blocker string }
type Status struct{ AuthID, OperationID, Purpose, Decision, ReceiptID, CleanupState string }
