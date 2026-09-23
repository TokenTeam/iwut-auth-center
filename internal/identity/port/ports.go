package port

import (
	"context"
	"iwut-auth-center/internal/identity/domain"
	"time"
)

// WithSession executes prepare in the same transaction as the authoritative
// session/credential/principal reads and monotonic usage update. It may retry
// prepare; only nil confirms commit. No candidate may escape before then.
type Repository interface {
	WithSession(context.Context, []byte, func(domain.Snapshot, time.Time) error) error
}
type Signer interface {
	Sign(context.Context, domain.Claims) (string, error)
}
type Tokens interface {
	TokenDigest(string) ([]byte, error)
	NewID() (string, error)
}
