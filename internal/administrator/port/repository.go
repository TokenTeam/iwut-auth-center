package port

import (
	"context"
	d "iwut-auth-center/internal/administrator/domain"
	"time"
)

type Repository interface {
	Manage(context.Context, d.Command) (d.State, error)
	Get(context.Context, string, string) (d.State, error)
	List(context.Context, string, string, int) (d.Page, error)
}
type Limiter interface {
	AllowBegin(string, time.Time) bool
	AllowComplete(string, time.Time) bool
}
