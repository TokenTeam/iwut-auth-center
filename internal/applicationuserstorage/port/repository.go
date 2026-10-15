package port

import (
	"context"
	"time"
)

type Repository interface {
	Clear(context.Context, string, string, time.Time) (bool, error)
}
