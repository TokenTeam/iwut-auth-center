package port

import (
	"context"
	"iwut-auth-center/internal/password/domain"
	"time"
)

type Reset struct {
	OperationID, RequestID, Email, AuthID, ServiceID, KeyID, Status string
	Acceptable                                                      bool
	AccountRevision, PasswordRevision, RoleRevision, FailedAttempts int64
	RequestMAC, CodeMAC, CompletionMAC                              []byte
	CreatedAt, ExpiresAt, ResendAfter, RetainUntil                  time.Time
}
type ResetSnapshot struct {
	Operation Reset
	Password  domain.Record
	Minimum   int64
}
type ResetRepository interface {
	BeginReset(context.Context, Reset, string, string, time.Time) (Reset, bool, error)
	ReadReset(context.Context, string, time.Time) (ResetSnapshot, error)
	FailReset(context.Context, string, time.Time) error
	CompleteReset(context.Context, ResetSnapshot, domain.Material, []byte, time.Time) error
}
type ResetProtocol interface {
	KeyID() string
	ServiceID() string
	ResetRequestMAC(string, string) ([]byte, error)
	ResetCodeMAC(string, string, int64, int64, int64, time.Time, []byte, string) ([]byte, error)
	ResetCompletionMAC(string, []byte, string) ([]byte, error)
}
type AddressBudget interface{ Key(string) string }
type ResetSender interface {
	Send(context.Context, string, string, string, time.Time) error
}

type Notification struct {
	EventID, AuthID, Email, Kind, LeaseID string
	Attempts                              int64
	ChangedAt                             time.Time
}
type NotificationRepository interface {
	PrunePasswordOperations(context.Context, time.Time) error
	ClaimNotification(context.Context, string, time.Time, time.Duration) (Notification, bool, error)
	FinishNotification(context.Context, Notification, bool, time.Time) error
}
type NotificationSender interface {
	SendPasswordNotification(context.Context, string, string, string, time.Time) error
}
