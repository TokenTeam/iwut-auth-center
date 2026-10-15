package port

import (
	"context"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/password/domain"
	"time"
)

type Snapshot struct {
	Session                   auth.Session
	Password                  domain.Record
	MinimumCredentialRevision int64
}

type Change struct {
	AuthID, RequestID, OperationID, SourceSessionID, RetainedCredentialID, KeyID string
	OriginalAccountRevision, OriginalPasswordRevision                            int64
	RequestMAC                                                                   []byte
	CreatedAt, RetainUntil                                                       time.Time
}

type ChangeCommit struct {
	Snapshot    Snapshot
	Operation   Change
	NewMaterial domain.Material
	Session     auth.Session
}

type ChangeRepository interface {
	ReadSnapshot(context.Context, []byte, time.Time) (Snapshot, error)
	FindChange(context.Context, []byte, string, time.Time) (Change, bool, error)
	CommitChange(context.Context, ChangeCommit, time.Time) error
}

type Quota interface {
	General(context.Context, string, string, time.Time) error
	OwnerRequest(context.Context, string, time.Time) error
	Work(context.Context, string, string, int, time.Time) error
}

type ChangeProtocol interface {
	KeyID() string
	ChangeMAC(string, string, string, int64, int64, string, string) ([]byte, error)
}
