package port

import (
	"context"
	"iwut-auth-center/internal/developer/domain"
	"time"
)

// Evaluate confirms the current Session and complete snapshot under the auth
// transaction fence. decide may be retried; true atomically activates and audits.
type ApplicationRepository interface {
	Evaluate(context.Context, []byte, func(domain.ApplicationState) (bool, error)) (domain.ApplicationState, error)
}
type ApplicationLimiter interface {
	AllowBegin(string, time.Time) bool
	AllowLocator(string, time.Time) bool
}
