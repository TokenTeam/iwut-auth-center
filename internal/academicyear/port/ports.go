package port

import (
	"context"
	"time"

	d "iwut-auth-center/internal/academicyear/domain"
)

type Repository interface {
	Get(context.Context, string) (d.Schedule, error)
	Update(context.Context, d.Command) (d.Schedule, error)
}

type Provider interface {
	CurrentAcademicYear(context.Context, time.Time) (int32, error)
}

type Limiter interface {
	AllowBegin(string, time.Time) bool
	AllowComplete(string, time.Time) bool
}
