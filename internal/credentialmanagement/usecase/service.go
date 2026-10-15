package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	p "iwut-auth-center/internal/credentialmanagement/port"
	pwd "iwut-auth-center/internal/password/domain"
	pp "iwut-auth-center/internal/password/port"
	"time"
	"unicode/utf8"
)

type Service struct {
	repo      p.Repository
	protocol  p.Protocol
	password  pp.PasswordVerifier
	limiter   p.Limiter
	serviceID string
	clock     func() time.Time
}

func New(r p.Repository, protocol p.Protocol, password pp.PasswordVerifier, limiter p.Limiter, serviceID string) (*Service, error) {
	if r == nil || protocol == nil || password == nil || limiter == nil || serviceID == "" {
		return nil, d.ErrUnavailable
	}
	return &Service{r, protocol, password, limiter, serviceID, time.Now}, nil
}
func (s *Service) SetClock(clock func() time.Time) { s.clock = clock }
func (s *Service) now() time.Time                  { return s.clock().UTC().Truncate(time.Millisecond) }
func (s *Service) admit(ctx context.Context, digest []byte) error {
	if len(digest) != 32 {
		return d.ErrSession
	}
	caller, err := s.repo.Authenticate(ctx, digest, s.now())
	if err != nil {
		return err
	}
	if !s.limiter.AllowAccount(caller.AuthID, s.now()) {
		return d.ErrRate
	}
	return nil
}
func (s *Service) List(ctx context.Context, digest []byte, size int, cursor string) (d.Page, error) {
	if size < 1 || size > 50 || (cursor != "" && !d.ValidID(cursor)) {
		return d.Page{}, d.ErrInvalid
	}
	if err := s.admit(ctx, digest); err != nil {
		return d.Page{}, err
	}
	return s.repo.List(ctx, digest, size, cursor, s.now())
}
func (s *Service) SetLabel(ctx context.Context, digest []byte, id, label string, revision int64) (d.LabelResult, error) {
	value, err := d.Label(label)
	if err != nil || !d.ValidID(id) || revision < 0 {
		return d.LabelResult{}, d.ErrInvalid
	}
	if err = s.admit(ctx, digest); err != nil {
		return d.LabelResult{}, err
	}
	event, err := s.protocol.NewID()
	if err != nil {
		return d.LabelResult{}, d.ErrUnavailable
	}
	return s.repo.SetLabel(ctx, digest, id, value, revision, event, s.now())
}
func (s *Service) Begin(ctx context.Context, digest []byte, request, target string) (d.Started, error) {
	if !d.ValidID(request) || !d.ValidID(target) {
		return d.Started{}, d.ErrInvalid
	}
	if err := s.admit(ctx, digest); err != nil {
		return d.Started{}, err
	}
	id, err := s.protocol.NewID()
	if err != nil {
		return d.Started{}, d.ErrUnavailable
	}
	challenge, err := s.protocol.RandomBytes(32)
	if err != nil {
		return d.Started{}, d.ErrUnavailable
	}
	now := s.now()
	op, err := s.repo.Begin(ctx, digest, d.Operation{OperationID: id, RequestID: request, TargetCredentialID: target, Purpose: d.Purpose, ServiceID: s.serviceID, ApplicationID: "iwut-client", Challenge: challenge, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), RetainUntil: now.Add(24 * time.Hour), Status: d.Pending}, now)
	if err != nil {
		return d.Started{}, err
	}
	payload, err := s.protocol.SigningPayload(op)
	if err != nil {
		return d.Started{}, d.ErrUnavailable
	}
	return d.Started{Operation: op, SigningPayload: payload}, nil
}
func (s *Service) Complete(ctx context.Context, digest []byte, id string, signature []byte, password, source string) error {
	if !d.ValidID(id) || !s.protocol.ValidSignature(signature) || password == "" || len(password) > 1024 || !utf8.ValidString(password) {
		return d.ErrInvalid
	}
	if err := s.admit(ctx, digest); err != nil {
		return err
	}
	op, err := s.repo.ReadForComplete(ctx, digest, id, s.now())
	if err != nil {
		return err
	}
	reject := func() error {
		if op.Status == d.Pending {
			if e := s.repo.Fail(ctx, digest, id, s.now()); e != nil {
				return e
			}
		}
		return d.ErrProof
	}
	payload, err := s.protocol.SigningPayload(op)
	if err != nil {
		return d.ErrUnavailable
	}
	if !s.protocol.Verify(op.PublicKey, payload, signature) {
		return reject()
	}
	revision, err := s.password.VerifyPassword(ctx, pp.ReauthRequest{AuthID: op.AuthID, CredentialID: op.CallerCredentialID, AccountRevision: op.AccountRevision, Password: password, Source: source})
	if err != nil {
		switch {
		case errors.Is(err, pwd.ErrAuthentication), errors.Is(err, pwd.ErrSessionInvalid):
			return reject()
		case errors.Is(err, pwd.ErrLimited):
			return d.ErrRate
		case errors.Is(err, pwd.ErrInvalidInput):
			return d.ErrInvalid
		default:
			return d.ErrUnavailable
		}
	}
	if revision != op.PasswordRevision {
		return d.ErrProof
	}
	event, err := s.protocol.NewID()
	if err != nil {
		return d.ErrUnavailable
	}
	return s.repo.Complete(ctx, digest, id, signature, revision, event, s.now())
}
