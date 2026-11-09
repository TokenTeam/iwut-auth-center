package port

import (
	"context"
	"iwut-auth-center/internal/managedusersearch/domain"
	"time"
)

type Repository interface {
	Search(context.Context, string, domain.Query) (domain.Result, error)
}
type Limiter interface{ AllowBegin(string, time.Time) bool }
