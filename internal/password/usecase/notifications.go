package usecase

import (
	"context"
	auth "iwut-auth-center/internal/authentication/port"
	p "iwut-auth-center/internal/password/port"
	"time"
)

type Notifications struct {
	repo    p.NotificationRepository
	sender  p.NotificationSender
	device  auth.DeviceProtocol
	timeout time.Duration
	now     func() time.Time
}

func NewNotifications(repo p.NotificationRepository, sender p.NotificationSender, device auth.DeviceProtocol, timeout time.Duration) *Notifications {
	return &Notifications{repo, sender, device, timeout, time.Now}
}
func (s *Notifications) SetClock(clock func() time.Time) { s.now = clock }
func (s *Notifications) Tick(ctx context.Context) error {
	if err := s.repo.PrunePasswordOperations(ctx, s.now()); err != nil {
		return err
	}
	if s.sender == nil {
		return nil
	}
	for i := 0; i < 32; i++ {
		lease, err := s.device.NewID()
		if err != nil {
			return err
		}
		n, found, err := s.repo.ClaimNotification(ctx, lease, s.now(), 2*s.timeout+time.Minute)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		sendCtx, cancel := context.WithTimeout(ctx, s.timeout)
		err = s.sender.SendPasswordNotification(sendCtx, n.Email, n.Kind, n.EventID, n.ChangedAt)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err = s.repo.FinishNotification(ctx, n, err == nil, s.now()); err != nil {
			return err
		}
	}
	return nil
}
