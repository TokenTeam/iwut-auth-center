package usecase

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	auth "iwut-auth-center/internal/authentication/domain"
	authport "iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/emaillogin/domain"
	"iwut-auth-center/internal/emaillogin/port"
	"time"
)

type Login struct {
	repository port.Repository
	protocol   port.Protocol
	device     authport.DeviceProtocol
	sender     port.Sender
	limiter    authport.Limiter
	serviceID  string
	sessionTTL time.Duration
	now        func() time.Time
}

func New(repository port.Repository, protocol port.Protocol, device authport.DeviceProtocol, sender port.Sender, limiter authport.Limiter, serviceID string, sessionTTL time.Duration) (*Login, error) {
	if repository == nil || protocol == nil || device == nil || sender == nil || limiter == nil || serviceID == "" || sessionTTL < time.Millisecond {
		return nil, domain.ErrUnavailable
	}
	return &Login{repository: repository, protocol: protocol, device: device, sender: sender, limiter: limiter, serviceID: serviceID, sessionTTL: sessionTTL, now: time.Now}, nil
}
func (u *Login) Begin(ctx context.Context, b domain.Begin) (domain.Challenge, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if !u.limiter.AllowBegin(b.Source, now) {
		return domain.Challenge{}, domain.ErrRate
	}
	email, err := u.protocol.NormalizeEmail(b.Email)
	if err != nil || !u.protocol.ValidID(b.RequestID) || b.ProtocolVersion != auth.ProtocolVersion {
		return domain.Challenge{}, domain.ErrInvalid
	}
	b.Email = email
	fingerprint, err := u.device.Fingerprint(b.PublicKey)
	if err != nil {
		return domain.Challenge{}, domain.ErrInvalid
	}
	id, err := u.device.NewID()
	if err != nil {
		return domain.Challenge{}, domain.ErrUnavailable
	}
	challenge, err := u.device.RandomBytes(32)
	if err != nil {
		return domain.Challenge{}, domain.ErrUnavailable
	}
	code, err := u.protocol.NewCode()
	if err != nil {
		return domain.Challenge{}, domain.ErrUnavailable
	}
	op := domain.Operation{OperationID: id, RequestID: b.RequestID, Purpose: domain.Purpose, ProtocolVersion: domain.ProtocolVersion, ServiceID: u.serviceID, ApplicationID: auth.ApplicationID, Email: b.Email, PublicKey: b.PublicKey, Fingerprint: fingerprint, Challenge: challenge, KeyID: u.protocol.KeyID(), Status: auth.Pending, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), ResendAfter: now.Add(time.Minute), RetainUntil: now.Add(24 * time.Hour)}
	op.RequestMAC = u.protocol.RequestMAC(b)
	op.CodeMAC = u.protocol.CodeMAC(op, code)
	op, created, err := u.repository.Begin(ctx, op, b.Source, now)
	if err != nil {
		return domain.Challenge{}, err
	}
	payload, err := u.protocol.Payload(op)
	if err != nil {
		return domain.Challenge{}, domain.ErrUnavailable
	}
	if created {
		if err := u.sender.Send(ctx, op.Email, domain.Purpose, code, op.ExpiresAt); err != nil {
			return domain.Challenge{}, domain.ErrDelivery
		}
	}
	return domain.Challenge{OperationID: op.OperationID, ProtocolVersion: op.ProtocolVersion, Challenge: op.Challenge, SigningPayload: payload, ExpiresAt: op.ExpiresAt, ResendAfter: op.ResendAfter}, nil
}
func (u *Login) Complete(ctx context.Context, id, code string, signature []byte, source string) (auth.Established, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if !u.limiter.AllowComplete("source:"+source, now) {
		return auth.Established{}, domain.ErrRate
	}
	if !u.protocol.ValidID(id) || !u.protocol.ValidCode(code) || !u.protocol.ValidSignature(signature) {
		return auth.Established{}, domain.ErrInvalid
	}
	op, err := u.repository.Get(ctx, id)
	if err != nil {
		return auth.Established{}, err
	}
	if !u.limiter.AllowLocator("email-login:"+hex.EncodeToString(op.Fingerprint), now) {
		return auth.Established{}, domain.ErrRate
	}
	if op.Purpose != domain.Purpose || op.ProtocolVersion != domain.ProtocolVersion {
		return auth.Established{}, domain.ErrFailed
	}
	if op.Status == auth.Completed {
		return auth.Established{}, domain.ErrCompleted
	}
	if op.Status != auth.Pending || op.KeyID != u.protocol.KeyID() || !now.Before(op.ExpiresAt) || op.FailedAttempts >= 5 {
		return auth.Established{}, domain.ErrFailed
	}
	payload, err := u.protocol.Payload(op)
	validCode := hmac.Equal(op.CodeMAC, u.protocol.CodeMAC(op, code))
	validProof := err == nil && u.device.Verify(op.PublicKey, payload, signature)
	if !validCode || !validProof || !op.Eligible || op.AuthID == "" || op.EmailBindingRevision <= 0 {
		return auth.Established{}, u.fail(ctx, id, now)
	}
	if !op.CredentialAcceptable {
		return auth.Established{}, domain.ErrCredential
	}
	credentialID, err := u.device.NewID()
	if err != nil {
		return auth.Established{}, domain.ErrUnavailable
	}
	sessionID, err := u.device.NewID()
	if err != nil {
		return auth.Established{}, domain.ErrUnavailable
	}
	token, digest, err := u.device.NewSessionToken()
	if err != nil {
		return auth.Established{}, domain.ErrUnavailable
	}
	session := auth.Session{AccountRevision: op.AccountRevision, SessionID: sessionID, AuthID: op.AuthID, CredentialID: credentialID, TokenDigest: digest, AuthenticationMethod: domain.AuthenticationMethod, EmailBindingRevision: op.EmailBindingRevision, AuthenticatedAt: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(u.sessionTTL)}
	credential := auth.Credential{CredentialID: credentialID, AuthID: op.AuthID, ProtocolVersion: auth.ProtocolVersion, PublicKey: op.PublicKey, Fingerprint: op.Fingerprint, CreatedAt: now}
	credentialID, err = u.repository.Complete(ctx, port.Commit{Operation: op, Credential: credential, Session: session}, now)
	if err != nil {
		return auth.Established{}, err
	}
	if !u.protocol.ValidID(credentialID) {
		return auth.Established{}, domain.ErrUnavailable
	}
	return auth.Established{AuthID: op.AuthID, CredentialID: credentialID, SessionID: sessionID, SessionToken: token, ExpiresAt: session.ExpiresAt}, nil
}
func (u *Login) fail(ctx context.Context, id string, now time.Time) error {
	if err := u.repository.Fail(ctx, id, now); err != nil {
		return err
	}
	return domain.ErrFailed
}

// Reject counts a transport-level invalid request in the same bounded request
// buckets as a well-formed request, without reading account or Session data.
func (u *Login) Reject(source string, begin bool) error {
	now := u.now().UTC().Truncate(time.Millisecond)
	if begin {
		if !u.limiter.AllowBegin(source, now) {
			return domain.ErrRate
		}
	} else if !u.limiter.AllowComplete("source:"+source, now) {
		return domain.ErrRate
	}
	return domain.ErrInvalid
}
