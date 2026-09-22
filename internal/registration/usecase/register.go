package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	auth "iwut-auth-center/internal/authentication/domain"
	authport "iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/registration/domain"
	"iwut-auth-center/internal/registration/port"
)

type Registration struct {
	repo      port.RegistrationRepository
	protocol  authport.DeviceProtocol
	cipher    port.AssociationCipher
	limiter   authport.Limiter
	serviceID string
	ttl       time.Duration
	now       func() time.Time
}

func NewRegistration(repo port.RegistrationRepository, protocol authport.DeviceProtocol, cipher port.AssociationCipher, limiter authport.Limiter, serviceID string, ttl time.Duration) (*Registration, error) {
	if repo == nil || protocol == nil || cipher == nil || limiter == nil || serviceID == "" || ttl < time.Millisecond {
		return nil, port.ErrUnavailable
	}
	return &Registration{repo: repo, protocol: protocol, cipher: cipher, limiter: limiter, serviceID: serviceID, ttl: ttl, now: time.Now}, nil
}

func (u *Registration) Begin(ctx context.Context, protocolVersion string, publicKey []byte, scheme string, token []byte, source string) (auth.Challenge, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if !u.limiter.AllowBegin(source, now) {
		return auth.Challenge{}, port.ErrRateLimited
	}
	if protocolVersion == "" || scheme == "" || len(token) != 32 || len(publicKey) == 0 {
		return auth.Challenge{}, port.ErrInvalidInput
	}
	if protocolVersion != auth.ProtocolVersion || scheme != domain.AssociationScheme {
		return auth.Challenge{}, port.ErrUnsupported
	}
	fingerprint, err := u.protocol.Fingerprint(publicKey)
	if err != nil {
		return auth.Challenge{}, port.ErrInvalidInput
	}
	id, err := u.protocol.NewID()
	if err != nil {
		return auth.Challenge{}, port.ErrUnavailable
	}
	challenge, err := u.protocol.RandomBytes(32)
	if err != nil {
		return auth.Challenge{}, port.ErrUnavailable
	}
	sealed, err := u.cipher.Seal("operation", id, scheme, token)
	if err != nil {
		return auth.Challenge{}, port.ErrUnavailable
	}
	digest, err := u.cipher.AssociationDigest(scheme, token)
	if err != nil {
		return auth.Challenge{}, port.ErrInvalidInput
	}
	op := auth.Operation{OperationID: id, Purpose: auth.Register, ProtocolVersion: protocolVersion, ServiceID: u.serviceID, ApplicationID: auth.ApplicationID, Challenge: challenge, ExpiresAt: now.Add(5 * time.Minute), CreatedAt: now, LocatorKind: auth.FingerprintLocator, LocatorValue: fingerprint, PublicKey: append([]byte(nil), publicKey...), Acceptable: true, Status: auth.Pending, SchemeVersion: sealed.SchemeVersion, KeyVersion: sealed.KeyVersion, LookupKey: sealed.LookupKey, Nonce: sealed.Nonce, Ciphertext: sealed.Ciphertext}
	payload, err := u.protocol.SigningPayload(op, digest)
	clear(digest)
	if err != nil {
		return auth.Challenge{}, port.ErrUnavailable
	}
	if err := u.repo.CreateOperation(ctx, op, now); err != nil {
		return auth.Challenge{}, registrationError(err)
	}
	return auth.Challenge{OperationID: id, ProtocolVersion: protocolVersion, Challenge: challenge, SigningPayload: payload, ExpiresAt: op.ExpiresAt}, nil
}

func (u *Registration) Complete(ctx context.Context, id string, signature []byte) (auth.Established, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if !u.limiter.AllowComplete("", now) {
		return auth.Established{}, port.ErrRateLimited
	}
	op, err := u.repo.GetOperation(ctx, id)
	if errors.Is(err, authport.ErrNotFound) {
		return auth.Established{}, port.ErrProofInvalid
	}
	if err != nil {
		return auth.Established{}, registrationError(err)
	}
	if !u.limiter.AllowLocator(fmt.Sprintf("%s:%x", op.LocatorKind, op.LocatorValue), now) {
		return auth.Established{}, port.ErrRateLimited
	}
	if op.Purpose != auth.Register {
		return auth.Established{}, port.ErrProofInvalid
	}
	if op.Status == auth.Completed {
		return auth.Established{}, port.ErrAlreadyCompleted
	}
	if op.Status != auth.Pending || !now.Before(op.ExpiresAt) {
		return auth.Established{}, u.fail(ctx, id, now)
	}
	// Normal requests must never use an old group even if rotation keys remain
	// in the environment after a successful startup gate.
	if op.KeyVersion != u.cipher.CurrentVersion() {
		return auth.Established{}, port.ErrUnavailable
	}
	sealed := domain.SealedAssociation{SchemeVersion: op.SchemeVersion, KeyVersion: op.KeyVersion, LookupKey: op.LookupKey, Nonce: op.Nonce, Ciphertext: op.Ciphertext}
	token, err := u.cipher.Open("operation", op.OperationID, sealed)
	if err != nil {
		return auth.Established{}, port.ErrUnavailable
	}
	defer clear(token)
	digest, err := u.cipher.AssociationDigest(op.SchemeVersion, token)
	if err != nil {
		return auth.Established{}, port.ErrUnavailable
	}
	payload, err := u.protocol.SigningPayload(op, digest)
	clear(digest)
	if err != nil || !op.Acceptable || !u.protocol.Verify(op.PublicKey, payload, signature) {
		return auth.Established{}, u.fail(ctx, id, now)
	}
	ids := make([]string, 4)
	for i := range ids {
		ids[i], err = u.protocol.NewID()
		if err != nil {
			return auth.Established{}, port.ErrUnavailable
		}
	}
	group, err := u.cipher.Seal("group", ids[3], op.SchemeVersion, token)
	if err != nil {
		return auth.Established{}, port.ErrUnavailable
	}
	secret, tokenDigest, err := u.protocol.NewSessionToken()
	if err != nil {
		return auth.Established{}, port.ErrUnavailable
	}
	credential := auth.Credential{CredentialID: ids[1], AuthID: ids[0], ProtocolVersion: op.ProtocolVersion, PublicKey: op.PublicKey, Fingerprint: op.LocatorValue, CreatedAt: now}
	session := auth.Session{SessionID: ids[2], AuthID: ids[0], CredentialID: ids[1], TokenDigest: tokenDigest, AuthenticationMethod: "DEVICE_CREDENTIAL", AuthenticatedAt: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(u.ttl)}
	commit := port.RegistrationCommit{Operation: op, Credential: credential, Session: session, Association: domain.Association{AssociationID: ids[3], SealedAssociation: group}}
	if err := u.repo.CompleteRegistration(ctx, commit, now); err != nil {
		return auth.Established{}, registrationError(err)
	}
	return auth.Established{AuthID: ids[0], CredentialID: ids[1], SessionID: ids[2], SessionToken: secret, ExpiresAt: session.ExpiresAt}, nil
}

func (u *Registration) fail(ctx context.Context, id string, now time.Time) error {
	if err := u.repo.RecordFailure(ctx, id, now); err != nil {
		return registrationError(err)
	}
	return port.ErrProofInvalid
}
func registrationError(err error) error {
	switch {
	case errors.Is(err, authport.ErrLimitExceeded):
		return port.ErrRateLimited
	case errors.Is(err, authport.ErrAlreadyCompleted):
		return port.ErrAlreadyCompleted
	case errors.Is(err, authport.ErrAuthenticationFailed):
		return port.ErrProofInvalid
	case errors.Is(err, port.ErrCredentialRegistered), errors.Is(err, authport.ErrCredentialRegistered):
		return port.ErrCredentialRegistered
	case errors.Is(err, port.ErrAlreadyCompleted):
		return port.ErrAlreadyCompleted
	default:
		return port.ErrUnavailable
	}
}
