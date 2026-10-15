package usecase

import (
	"context"
	"crypto/hmac"
	auth "iwut-auth-center/internal/authentication/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
	"time"
)

type ResetService struct {
	repository p.ResetRepository
	protocol   p.ResetProtocol
	device     auth.DeviceProtocol
	engine     p.Engine
	quota      p.Quota
	sender     p.ResetSender
	serviceID  string
	budget     p.AddressBudget
	now        func() time.Time
}

func NewResetService(r p.ResetRepository, protocol p.ResetProtocol, device auth.DeviceProtocol, engine p.Engine, quota p.Quota, sender p.ResetSender, service string, budget p.AddressBudget) (*ResetService, error) {
	if r == nil || protocol == nil || device == nil || engine == nil || quota == nil || sender == nil || service == "" || budget == nil {
		return nil, d.ErrUnavailable
	}
	return &ResetService{r, protocol, device, engine, quota, sender, service, budget, time.Now}, nil
}
func (s *ResetService) SetClock(clock func() time.Time) { s.now = clock }
func (s *ResetService) resetBudget(o p.Reset) string {
	if o.Acceptable {
		return o.AuthID
	}
	return s.budget.Key(o.Email)
}
func (s *ResetService) Begin(ctx context.Context, request, address, source string) (p.Reset, error) {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, source, "", now); err != nil {
		return p.Reset{}, err
	}
	address, err := email.NormalizeEmail(address)
	if err != nil {
		return p.Reset{}, d.ErrInvalidInput
	}
	id, err := s.device.NewID()
	if err != nil {
		return p.Reset{}, d.ErrUnavailable
	}
	dummy, err := s.device.NewID()
	if err != nil {
		return p.Reset{}, d.ErrUnavailable
	}
	tag, err := s.protocol.ResetRequestMAC(request, address)
	if err != nil {
		return p.Reset{}, d.ErrInvalidInput
	}
	// Uniform random digits, never persisted or returned to an anonymous caller.
	code := ""
	for len(code) < 8 {
		raw, e := s.device.RandomBytes(16)
		if e != nil {
			return p.Reset{}, d.ErrUnavailable
		}
		for _, b := range raw {
			if b < 250 && len(code) < 8 {
				code += string('0' + b%10)
			}
		}
	}
	o := p.Reset{OperationID: id, RequestID: request, Email: address, AuthID: dummy, ServiceID: s.serviceID, KeyID: s.protocol.KeyID(), Status: "PENDING", AccountRevision: 1, PasswordRevision: 1, RoleRevision: 1, RequestMAC: tag, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), ResendAfter: now.Add(time.Minute), RetainUntil: now.Add(24 * time.Hour)}
	o, fresh, err := s.repository.BeginReset(ctx, o, code, source, now)
	if err != nil {
		return p.Reset{}, err
	}
	if fresh && o.Acceptable {
		if err = s.sender.Send(ctx, o.Email, "RESET_PASSWORD", code, o.ExpiresAt); err != nil {
			return p.Reset{}, d.ErrDelivery
		}
	}
	return o, nil
}
func (s *ResetService) Complete(ctx context.Context, id, code, next, source string) error {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, source, "", now); err != nil {
		return err
	}
	if !d.ValidOperationID(id) || !email.ValidCode(code) {
		return d.ErrInvalidInput
	}
	normalized, err := s.engine.Normalize(next)
	if err != nil {
		return err
	}
	snapshot, err := s.repository.ReadReset(ctx, id, now)
	if err != nil {
		return err
	}
	o := snapshot.Operation
	if err = s.quota.OwnerRequest(ctx, s.resetBudget(o), now); err != nil {
		return err
	}
	mac, err := s.protocol.ResetCodeMAC(o.OperationID, o.AuthID, o.RoleRevision, o.PasswordRevision, o.AccountRevision, o.ExpiresAt, o.RequestMAC, code)
	if err != nil {
		return d.ErrUnavailable
	}
	if !o.Acceptable || !hmac.Equal(mac, o.CodeMAC) {
		if err = s.repository.FailReset(ctx, id, now); err != nil {
			return err
		}
		return d.ErrReset
	}
	completion, err := s.protocol.ResetCompletionMAC(id, mac, normalized)
	if err != nil {
		return d.ErrUnavailable
	}
	if o.Status == "COMPLETED" {
		return s.repository.CompleteReset(ctx, snapshot, d.Material{}, completion, now)
	}
	if _, err = s.engine.ValidateNew(next); err != nil {
		return err
	}
	if err = s.quota.Work(ctx, source, s.resetBudget(o), 2, now); err != nil {
		return err
	}
	unchanged, err := s.engine.Verify(ctx, next, snapshot.Password.Material)
	if err != nil {
		return err
	}
	if unchanged {
		return d.ErrUnchanged
	}
	material, err := s.engine.Hash(ctx, next)
	if err != nil {
		return err
	}
	return s.repository.CompleteReset(ctx, snapshot, material, completion, s.now().UTC().Truncate(time.Millisecond))
}
