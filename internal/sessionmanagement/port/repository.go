package port

import (
	"context"
	"iwut-auth-center/internal/sessionmanagement/domain"
	"time"
)

type Repository interface {
	Authenticate(context.Context, []byte, time.Time) (string, error)
	List(context.Context, []byte, int, string, time.Time) (domain.Page, error)
	Revoke(context.Context, []byte, []string, string, time.Time) error
}
type IDGenerator interface{ NewID() (string, error) }
type AccountLimiter interface{ AllowAccount(string, time.Time) bool }
