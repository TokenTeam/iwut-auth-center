package usecase

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	d "iwut-auth-center/internal/emailbinding/domain"
	"iwut-auth-center/internal/emailbinding/port"
	reg "iwut-auth-center/internal/registration/domain"
	rp "iwut-auth-center/internal/registration/port"
	"time"
)

type Service struct {
	repo      port.Repository
	protocol  port.Protocol
	device    ap.DeviceProtocol
	cipher    rp.AssociationCipher
	sender    port.Sender
	limiter   ap.Limiter
	serviceID string
	ttl       time.Duration
	now       func() time.Time
}

func New(repo port.Repository, p port.Protocol, device ap.DeviceProtocol, cipher rp.AssociationCipher, sender port.Sender, limiter ap.Limiter, service string, ttl time.Duration) (*Service, error) {
	if repo == nil || p == nil || device == nil || cipher == nil || sender == nil || limiter == nil || service == "" || ttl <= 0 {
		return nil, d.ErrUnavailable
	}
	return &Service{repo, p, device, cipher, sender, limiter, service, ttl, time.Now}, nil
}

// Authorize distinguishes absence at the transport boundary. Only an absent carrier passes nil.
func (u *Service) Authorize(ctx context.Context, token *string) ([]byte, error) {
	if token == nil {
		return nil, nil
	}
	digest, e := u.device.TokenDigest(*token)
	if e != nil {
		return nil, d.ErrSession
	}
	_, e = u.repo.CheckSession(ctx, digest, u.now())
	if e != nil {
		return nil, mapError(e)
	}
	return digest, nil
}
func (u *Service) Begin(ctx context.Context, b d.Begin, digest []byte) (port.Started, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if !u.limiter.AllowBegin(b.Source, now) {
		return port.Started{}, d.ErrRate
	}
	email, e := d.NormalizeEmail(b.Email)
	if e != nil || !u.protocol.ValidID(b.RequestID) {
		return port.Started{}, d.ErrInvalid
	}
	b.Email = email
	if b.Mode != d.Register && b.Mode != d.Bind {
		return port.Started{}, d.ErrInvalid
	}
	var caller auth.Session
	if len(digest) > 0 {
		caller, e = u.repo.CheckSession(ctx, digest, now)
		if e != nil {
			return port.Started{}, mapError(e)
		}
	}
	if (b.Mode == d.Register) != (len(digest) == 0) {
		return port.Started{}, d.ErrFlow
	}
	var fingerprint []byte
	if b.Mode == d.Register {
		if b.Revision != nil || b.ProtocolVersion != auth.ProtocolVersion || b.Scheme != reg.AssociationScheme || len(b.Token) != 32 {
			return port.Started{}, d.ErrInvalid
		}
		fingerprint, e = u.device.Fingerprint(b.PublicKey)
		if e != nil {
			return port.Started{}, d.ErrInvalid
		}
	} else if b.Revision == nil || *b.Revision < 0 || len(b.PublicKey) > 0 || len(b.Token) > 0 {
		return port.Started{}, d.ErrInvalid
	}
	id, e := u.device.NewID()
	if e != nil {
		return port.Started{}, d.ErrUnavailable
	}
	op := port.Operation{RequestID: b.RequestID, Mode: b.Mode, Email: b.Email, KeyID: u.protocol.KeyID(), RequestMAC: u.protocol.RequestMAC(b, caller.AuthID), ResendAfter: now.Add(time.Minute), RetainUntil: now.Add(24 * time.Hour), Owner: caller.AuthID}
	op.Proof = auth.Operation{OperationID: id, Purpose: d.BindingPurpose, ServiceID: u.serviceID, ApplicationID: auth.ApplicationID, ExpiresAt: now.Add(10 * time.Minute), CreatedAt: now, Status: auth.Pending, Acceptable: true, AuthID: caller.AuthID}
	if b.Mode == d.Register {
		op.Owner = hex.EncodeToString(fingerprint)
		op.Proof.Purpose = d.RegistrationPurpose
		op.Proof.ProtocolVersion = auth.ProtocolVersion
		op.Proof.PublicKey = append([]byte(nil), b.PublicKey...)
		op.Proof.LocatorKind = auth.FingerprintLocator
		op.Proof.LocatorValue = fingerprint
		op.Proof.Challenge, e = u.device.RandomBytes(32)
		if e != nil {
			return port.Started{}, d.ErrUnavailable
		}
		sealed, e := u.cipher.Seal("operation", id, b.Scheme, b.Token)
		if e != nil {
			return port.Started{}, d.ErrUnavailable
		}
		op.Proof.SchemeVersion = sealed.SchemeVersion
		op.Proof.KeyVersion = sealed.KeyVersion
		op.Proof.LookupKey = sealed.LookupKey
		op.Proof.Nonce = sealed.Nonce
		op.Proof.Ciphertext = sealed.Ciphertext
	} else {
		op.Revision = *b.Revision
	}
	code, e := u.protocol.NewCode()
	if e != nil {
		return port.Started{}, d.ErrUnavailable
	}
	op.CodeMAC = u.protocol.CodeMAC(op, code)
	saved, fresh, e := u.repo.Begin(ctx, op, digest, b.Source, now)
	if e != nil {
		return port.Started{}, mapError(e)
	}
	result := port.Started{Operation: saved}
	if saved.Mode == d.Register {
		token, e := u.open(saved)
		if e != nil {
			return port.Started{}, e
		}
		defer clear(token)
		sum, e := u.cipher.AssociationDigest(saved.Proof.SchemeVersion, token)
		if e != nil {
			return port.Started{}, d.ErrUnavailable
		}
		defer clear(sum)
		result.SigningPayload, e = u.protocol.Payload(saved, sum)
		if e != nil {
			return port.Started{}, d.ErrUnavailable
		}
	}
	if fresh {
		if e := u.sender.Send(ctx, saved.Email, saved.Proof.Purpose, code, saved.Proof.ExpiresAt); e != nil {
			return port.Started{}, d.ErrDelivery
		}
	}
	return result, nil
}
func (u *Service) Complete(ctx context.Context, id, code string, signature []byte, proofPresent bool, digest []byte) (port.Activated, error) {
	now := u.now().UTC().Truncate(time.Millisecond)
	if !u.limiter.AllowComplete("", now) {
		return port.Activated{}, d.ErrRate
	}
	if !u.protocol.ValidID(id) || !d.ValidCode(code) {
		return port.Activated{}, d.ErrInvalid
	}
	op, e := u.repo.Get(ctx, id)
	if e != nil {
		return port.Activated{}, mapError(e)
	}
	if !u.limiter.AllowLocator("email:"+op.Owner, now) {
		return port.Activated{}, d.ErrRate
	}
	if op.Mode == d.Register && len(digest) > 0 {
		return port.Activated{}, d.ErrFlow
	}
	if op.Mode == d.Bind && len(digest) == 0 {
		return port.Activated{}, d.ErrSession
	}
	if len(digest) > 0 {
		caller, e := u.repo.CheckSession(ctx, digest, now)
		if e != nil {
			return port.Activated{}, mapError(e)
		}
		if caller.AuthID != op.Owner {
			return port.Activated{}, d.ErrVerification
		}
	}
	if op.Mode == d.Register && op.Proof.Status == auth.Completed {
		return port.Activated{}, d.ErrCompleted
	}
	if op.Mode == d.Bind && proofPresent || op.Mode == d.Register && (!proofPresent || len(signature) == 0) {
		return port.Activated{}, d.ErrInvalid
	}
	if op.KeyID != u.protocol.KeyID() || !now.Before(op.RetainUntil) {
		return port.Activated{}, d.ErrVerification
	}
	if op.Proof.Status != auth.Completed && (op.Proof.Status != auth.Pending || !now.Before(op.Proof.ExpiresAt) || op.Proof.FailedAttempts >= 5) {
		return port.Activated{}, u.fail(ctx, id, now)
	}
	if !hmac.Equal(op.CodeMAC, u.protocol.CodeMAC(op, code)) {
		return port.Activated{}, u.fail(ctx, id, now)
	}
	var commit *rp.RegistrationCommit
	var established *auth.Established
	if op.Mode == d.Register {
		token, e := u.open(op)
		if e != nil {
			return port.Activated{}, e
		}
		defer clear(token)
		sum, e := u.cipher.AssociationDigest(op.Proof.SchemeVersion, token)
		if e != nil {
			return port.Activated{}, d.ErrUnavailable
		}
		defer clear(sum)
		payload, e := u.protocol.Payload(op, sum)
		if e != nil || !u.device.Verify(op.Proof.PublicKey, payload, signature) {
			return port.Activated{}, u.fail(ctx, id, now)
		}
		ids := make([]string, 4)
		for i := range ids {
			ids[i], e = u.device.NewID()
			if e != nil {
				return port.Activated{}, d.ErrUnavailable
			}
		}
		group, e := u.cipher.Seal("group", ids[3], op.Proof.SchemeVersion, token)
		if e != nil {
			return port.Activated{}, d.ErrUnavailable
		}
		secret, sd, e := u.device.NewSessionToken()
		if e != nil {
			return port.Activated{}, d.ErrUnavailable
		}
		credential := auth.Credential{CredentialID: ids[1], AuthID: ids[0], ProtocolVersion: auth.ProtocolVersion, PublicKey: op.Proof.PublicKey, Fingerprint: op.Proof.LocatorValue, CreatedAt: now}
		session := auth.Session{SessionID: ids[2], AuthID: ids[0], CredentialID: ids[1], TokenDigest: sd, AuthenticationMethod: "DEVICE_CREDENTIAL", AuthenticatedAt: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(u.ttl)}
		commit = &rp.RegistrationCommit{Operation: op.Proof, Credential: credential, Session: session, Association: reg.Association{AssociationID: ids[3], SealedAssociation: group}}
		established = &auth.Established{AuthID: ids[0], CredentialID: ids[1], SessionID: ids[2], SessionToken: secret, ExpiresAt: session.ExpiresAt}
	}
	result, e := u.repo.Complete(ctx, op, digest, commit, now)
	if e != nil {
		return port.Activated{}, mapError(e)
	}
	result.Registration = established
	return result, nil
}
func (u *Service) Own(ctx context.Context, digest []byte) (port.Binding, error) {
	if len(digest) == 0 {
		return port.Binding{}, d.ErrSession
	}
	now := u.now()
	if !u.limiter.AllowComplete("", now) {
		return port.Binding{}, d.ErrRate
	}
	r, e := u.repo.Own(ctx, digest, now)
	return r, mapError(e)
}
func (u *Service) open(o port.Operation) ([]byte, error) {
	a := o.Proof
	if a.KeyVersion != u.cipher.CurrentVersion() {
		return nil, d.ErrVerification
	}
	p, e := u.cipher.Open("operation", a.OperationID, reg.SealedAssociation{SchemeVersion: a.SchemeVersion, KeyVersion: a.KeyVersion, LookupKey: a.LookupKey, Nonce: a.Nonce, Ciphertext: a.Ciphertext})
	if e != nil {
		return nil, d.ErrUnavailable
	}
	return p, nil
}
func (u *Service) fail(ctx context.Context, id string, now time.Time) error {
	if e := u.repo.Fail(ctx, id, now); e != nil {
		return mapError(e)
	}
	return d.ErrVerification
}
func mapError(e error) error {
	if e == nil {
		return nil
	}
	for _, known := range d.Errors {
		if errors.Is(e, known) {
			return known
		}
	}
	switch {
	case errors.Is(e, ap.ErrSessionInvalid):
		return d.ErrSession
	case errors.Is(e, ap.ErrCredentialRegistered):
		return d.ErrCredential
	case errors.Is(e, ap.ErrAlreadyCompleted):
		return d.ErrCompleted
	case errors.Is(e, ap.ErrAuthenticationFailed), errors.Is(e, ap.ErrNotFound):
		return d.ErrVerification
	case errors.Is(e, ap.ErrLimitExceeded):
		return d.ErrRate
	default:
		return d.ErrUnavailable
	}
}
