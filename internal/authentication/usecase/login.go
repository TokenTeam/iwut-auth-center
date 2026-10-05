package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
)

type Login struct {
	repository port.LoginRepository
	protocol   port.DeviceProtocol
	limiter    port.Limiter
	serviceID  string
	ttl        time.Duration
	now        func() time.Time
}

func NewLogin(repository port.LoginRepository, protocol port.DeviceProtocol, limiter port.Limiter, serviceID string, ttl time.Duration) (*Login, error) {
	if repository == nil || protocol == nil || limiter == nil || serviceID == "" || ttl < time.Millisecond {
		return nil, port.ErrUnavailable
	}
	return &Login{repository: repository, protocol: protocol, limiter: limiter, serviceID: serviceID, ttl: ttl, now: time.Now}, nil
}

func (u *Login) Begin(ctx context.Context, locator domain.Locator, source string) (domain.Challenge, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if !u.limiter.AllowBegin(source, now) {
		return domain.Challenge{}, port.ErrLimitExceeded
	}
	opID, err := u.protocol.NewID()
	if err != nil {
		return domain.Challenge{}, port.ErrUnavailable
	}
	challenge, err := u.protocol.RandomBytes(32)
	if err != nil {
		return domain.Challenge{}, port.ErrUnavailable
	}
	op := domain.Operation{OperationID: opID, Purpose: domain.Login, ProtocolVersion: domain.ProtocolVersion, ServiceID: u.serviceID, ApplicationID: domain.ApplicationID, Challenge: challenge, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), LocatorKind: locator.Kind, LocatorValue: locator.Value, Status: domain.Pending}
	payload, err := u.protocol.SigningPayload(op, nil)
	if err != nil {
		return domain.Challenge{}, port.ErrInvalidInput
	}
	credential, acceptable, err := u.repository.ResolveCredential(ctx, locator)
	if err != nil {
		return domain.Challenge{}, err
	}
	if acceptable {
		op.AccountRevision = credential.AccountRevision
		op.Acceptable = true
		op.AuthID = credential.AuthID
		op.CredentialID = credential.CredentialID
		op.PublicKey = credential.PublicKey
	}
	if err := u.repository.CreateOperation(ctx, op, now); err != nil {
		return domain.Challenge{}, err
	}
	return domain.Challenge{OperationID: opID, ProtocolVersion: domain.ProtocolVersion, Challenge: challenge, SigningPayload: payload, ExpiresAt: op.ExpiresAt}, nil
}

func (u *Login) Complete(ctx context.Context, operationID string, signature []byte) (domain.Established, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	// Global rate accounting precedes lookup, including unknown IDs and malformed proofs.
	if !u.limiter.AllowComplete("", now) {
		return domain.Established{}, port.ErrLimitExceeded
	}
	op, err := u.repository.GetOperation(ctx, operationID)
	if errors.Is(err, port.ErrNotFound) {
		return domain.Established{}, port.ErrAuthenticationFailed
	}
	if err != nil {
		return domain.Established{}, err
	}
	limitLocator := fmt.Sprintf("%s:%x", op.LocatorKind, op.LocatorValue)
	if op.Acceptable && op.CredentialID != "" {
		limitLocator = "credential:" + op.CredentialID
	}
	if !u.limiter.AllowLocator(limitLocator, now) {
		return domain.Established{}, port.ErrLimitExceeded
	}
	if op.Purpose != domain.Login {
		return domain.Established{}, port.ErrAuthenticationFailed
	}
	if op.Status == domain.Completed {
		return domain.Established{}, port.ErrAlreadyCompleted
	}
	if op.Status != domain.Pending || !now.Before(op.ExpiresAt) {
		return domain.Established{}, u.fail(ctx, op.OperationID, now)
	}
	payload, err := u.protocol.SigningPayload(op, nil)
	if err != nil || !op.Acceptable || !u.protocol.Verify(op.PublicKey, payload, signature) {
		return domain.Established{}, u.fail(ctx, op.OperationID, now)
	}
	sessionID, err := u.protocol.NewID()
	if err != nil {
		return domain.Established{}, port.ErrUnavailable
	}
	token, digest, err := u.protocol.NewSessionToken()
	if err != nil {
		return domain.Established{}, port.ErrUnavailable
	}
	session := domain.Session{AccountRevision: op.AccountRevision, SessionID: sessionID, AuthID: op.AuthID, CredentialID: op.CredentialID, TokenDigest: digest, AuthenticationMethod: "DEVICE_CREDENTIAL", AuthenticatedAt: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(u.ttl)}
	if err := u.repository.CompleteLogin(ctx, op, session, now); err != nil {
		return domain.Established{}, err
	}
	return domain.Established{AuthID: session.AuthID, CredentialID: session.CredentialID, SessionID: sessionID, SessionToken: token, ExpiresAt: session.ExpiresAt}, nil
}

func (u *Login) fail(ctx context.Context, id string, now time.Time) error {
	if err := u.repository.RecordFailure(ctx, id, now); err != nil {
		return err
	}
	return port.ErrAuthenticationFailed
}

func (u *Login) Check(ctx context.Context, token string) (domain.Session, error) {
	digest, err := u.protocol.TokenDigest(token)
	if err != nil {
		return domain.Session{}, port.ErrSessionInvalid
	}
	return u.repository.CheckSession(ctx, digest, u.now().UTC().Truncate(time.Millisecond))
}

var _ port.SessionChecker = (*Login)(nil)
