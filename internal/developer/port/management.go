package port

import (
	"context"
	d "iwut-auth-center/internal/developer/domain"
	"time"
)

type ManagementRepository interface {
	ManageDeveloperStatus(context.Context, d.ManageDeveloperCommand) (d.ManagedDeveloperState, error)
	GetManagedDeveloperStatus(context.Context, string, string) (d.ManagedDeveloperState, error)
}
type ManagementLimiter interface {
	AllowBegin(string, time.Time) bool
	AllowComplete(string, time.Time) bool
}
