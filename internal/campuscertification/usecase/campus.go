package usecase

import (
	"context"
	"crypto/hmac"
	"errors"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/campuscertification/domain"
	"iwut-auth-center/internal/campuscertification/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	"time"
)

type Service struct {
	repo      port.Repository
	protocol  port.Protocol
	device    ap.DeviceProtocol
	sender    port.Sender
	limiter   ap.Limiter
	serviceID string
	now       func() time.Time
}

func New(repo port.Repository, p port.Protocol, device ap.DeviceProtocol, sender port.Sender, limiter ap.Limiter, serviceID string) (*Service, error) {
	if repo == nil || p == nil || device == nil || sender == nil || limiter == nil || serviceID == "" {
		return nil, d.ErrUnavailable
	}
	return &Service{repo, p, device, sender, limiter, serviceID, time.Now}, nil
}

func (u *Service) Authorize(ctx context.Context, token string) ([]byte, error) {
	digest, err := u.device.TokenDigest(token)
	if err != nil {
		return nil, d.ErrSession
	}
	_, err = u.repo.CheckSession(ctx, digest, u.now())
	if err != nil {
		return nil, mapError(err)
	}
	return digest, nil
}

func (u *Service) Begin(ctx context.Context, b d.Begin, digest []byte) (port.Operation, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if len(digest) != 32 {
		return port.Operation{}, d.ErrSession
	}
	if !u.limiter.AllowBegin(b.Source, now) {
		return port.Operation{}, d.ErrRate
	}
	emailAddress, err := email.NormalizeEmail(b.Email)
	if err != nil || !d.IsWHUTEmail(emailAddress) || !u.protocol.ValidID(b.RequestID) {
		return port.Operation{}, d.ErrInvalid
	}
	b.Email = emailAddress
	caller, err := u.repo.CheckSession(ctx, digest, now)
	if err != nil {
		return port.Operation{}, mapError(err)
	}
	id, err := u.device.NewID()
	if err != nil {
		return port.Operation{}, d.ErrUnavailable
	}
	op := port.Operation{RequestID: b.RequestID, Email: b.Email, KeyID: u.protocol.KeyID(), RequestMAC: u.protocol.RequestMAC(b, caller.AuthID, caller.AccountRevision), ResendAfter: now.Add(time.Minute), RetainUntil: now.Add(24 * time.Hour)}
	op.Proof = auth.Operation{OperationID: id, Purpose: d.Purpose, ServiceID: u.serviceID, ApplicationID: auth.ApplicationID, AuthID: caller.AuthID, AccountRevision: caller.AccountRevision, ExpiresAt: now.Add(10 * time.Minute), CreatedAt: now, Status: auth.Pending, Acceptable: true}
	code, err := u.protocol.NewCode()
	if err != nil {
		return port.Operation{}, d.ErrUnavailable
	}
	op.CodeMAC = u.protocol.CodeMAC(op, code)
	saved, fresh, err := u.repo.Begin(ctx, op, digest, b.Source, now)
	if err != nil {
		return port.Operation{}, mapError(err)
	}
	if fresh {
		if err = u.sender.Send(ctx, saved.Email, d.Purpose, code, saved.Proof.ExpiresAt); err != nil {
			return port.Operation{}, d.ErrDelivery
		}
	}
	return saved, nil
}

func (u *Service) Complete(ctx context.Context, id, code string, digest []byte) (d.Certification, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if len(digest) != 32 {
		return d.Certification{}, d.ErrSession
	}
	if !u.limiter.AllowComplete("", now) {
		return d.Certification{}, d.ErrRate
	}
	if !u.protocol.ValidID(id) || !email.ValidCode(code) {
		return d.Certification{}, d.ErrInvalid
	}
	op, err := u.repo.Get(ctx, id)
	if err != nil {
		return d.Certification{}, mapError(err)
	}
	if op.KeyID != u.protocol.KeyID() || op.Proof.Purpose != d.Purpose || op.Proof.ServiceID != u.serviceID || op.Proof.ApplicationID != auth.ApplicationID || !hmac.Equal(op.RequestMAC, u.protocol.RequestMAC(d.Begin{RequestID: op.RequestID, Email: op.Email}, op.Proof.AuthID, op.Proof.AccountRevision)) {
		return d.Certification{}, d.ErrVerification
	}
	caller, err := u.repo.CheckSession(ctx, digest, now)
	if err != nil {
		return d.Certification{}, mapError(err)
	}
	if caller.AuthID != op.Proof.AuthID || caller.AccountRevision != op.Proof.AccountRevision {
		return d.Certification{}, d.ErrVerification
	}
	if !u.limiter.AllowLocator("campus:"+caller.AuthID, now) {
		return d.Certification{}, d.ErrRate
	}
	op.CodeMAC = u.protocol.CodeMAC(op, code)
	result, err := u.repo.Complete(ctx, op, digest, now)
	return result, mapError(err)
}

func (u *Service) Own(ctx context.Context, digest []byte) (d.Certification, error) {
	if len(digest) != 32 {
		return d.Certification{}, d.ErrSession
	}
	now := u.now().UTC().Truncate(time.Millisecond)
	if !u.limiter.AllowComplete("", now) {
		return d.Certification{}, d.ErrRate
	}
	result, err := u.repo.Own(ctx, digest, now)
	if errors.Is(err, d.ErrNotFound) {
		return d.Certification{}, nil
	}
	return result, mapError(err)
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{d.ErrInvalid, d.ErrSession, d.ErrVerification, d.ErrConflict, d.ErrCertified, d.ErrRate, d.ErrDelivery, d.ErrUnavailable, d.ErrNotFound} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, ap.ErrSessionInvalid) || errors.Is(err, ap.ErrAuthenticationFailed) {
		return d.ErrSession
	}
	if errors.Is(err, email.ErrRate) {
		return d.ErrRate
	}
	return d.ErrUnavailable
}
