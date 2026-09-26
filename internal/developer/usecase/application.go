package usecase

import (
	"context"
	"iwut-auth-center/internal/developer/domain"
	"iwut-auth-center/internal/developer/port"
	"time"
)

type Application struct {
	repository port.ApplicationRepository
	limiter    port.ApplicationLimiter
	ready      bool
}

func NewApplication(r port.ApplicationRepository, l port.ApplicationLimiter, ready bool) *Application {
	return &Application{r, l, ready}
}
func (a *Application) AdmitSource(source string) error {
	if a == nil || a.repository == nil || a.limiter == nil {
		return domain.ErrApplicationUnavailable
	}
	if !a.limiter.AllowBegin(source, time.Now().UTC()) {
		return domain.ErrApplicationRate
	}
	return nil
}
func (a *Application) Execute(ctx context.Context, digest []byte, apply bool, candidate string) (domain.ApplicationState, []domain.ApplicationBlocker, error) {
	if a == nil || a.repository == nil || a.limiter == nil {
		return domain.ApplicationState{}, nil, domain.ErrApplicationUnavailable
	}
	if len(digest) != 32 {
		return domain.ApplicationState{}, nil, domain.ErrApplicationSession
	}
	admitted := ""
	s, err := a.repository.Evaluate(ctx, digest, func(s domain.ApplicationState) (domain.HandleClaim, error) {
		if !s.Valid() {
			return domain.HandleClaim{}, domain.ErrApplicationUnavailable
		}
		// Mongo retries do not consume additional account quota.
		if admitted != s.AuthID {
			if !a.limiter.AllowLocator(s.AuthID, time.Now().UTC()) {
				return domain.HandleClaim{}, domain.ErrApplicationRate
			}
			admitted = s.AuthID
		}
		if apply {
			claim, err := s.Apply(a.ready, candidate)
			if err != nil || !claim {
				return domain.HandleClaim{}, err
			}
			handle, _ := domain.NormalizeDeveloperHandle(candidate)
			return domain.HandleClaim{DeveloperHandle: handle}, nil
		}
		return domain.HandleClaim{}, nil
	})
	if err != nil {
		return domain.ApplicationState{}, nil, err
	}
	return s, s.Blockers(a.ready), nil
}
