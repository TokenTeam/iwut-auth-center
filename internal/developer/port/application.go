package port

import (
	"context"
	"iwut-auth-center/internal/developer/domain"
	"time"
)

// Evaluate confirms the current Session and complete snapshot under the auth
// transaction fence. decide may be retried; a non-empty claim atomically reserves the handle and audits.
type ApplicationRepository interface {
	Evaluate(context.Context, []byte, func(domain.ApplicationState) (domain.HandleClaim, error)) (domain.ApplicationState, error)
}
type ApplicationLimiter interface {
	AllowBegin(string, time.Time) bool
	AllowLocator(string, time.Time) bool
}
