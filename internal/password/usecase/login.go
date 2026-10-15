package usecase

import (
	"context"
	auth "iwut-auth-center/internal/authentication/domain"
	ap "iwut-auth-center/internal/authentication/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
	"time"
)

type LoginService struct {
	repo     p.LoginRepository
	engine   p.RehashEngine
	protocol p.LoginProtocol
	device   ap.DeviceProtocol
	quota    p.Quota
	budget   p.AddressBudget
	dummy    d.Material
	ttl      time.Duration
	now      func() time.Time
}

func NewLoginService(repo p.LoginRepository, engine p.RehashEngine, protocol p.LoginProtocol, device ap.DeviceProtocol, quota p.Quota, budget p.AddressBudget, dummy d.Material, ttl time.Duration) (*LoginService, error) {
	if repo == nil || engine == nil || protocol == nil || device == nil || quota == nil || budget == nil || !dummy.Valid() || ttl <= 0 || ttl > 365*24*time.Hour {
		return nil, d.ErrUnavailable
	}
	return &LoginService{repo, engine, protocol, device, quota, budget, dummy, ttl, time.Now}, nil
}
func (s *LoginService) SetClock(now func() time.Time) { s.now = now }
func (s *LoginService) Begin(ctx context.Context, requestID, address, version string, key []byte, source string) (auth.Challenge, error) {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, source, "", now); err != nil {
		return auth.Challenge{}, err
	}
	address, err := email.NormalizeEmail(address)
	if err != nil || !d.ValidOperationID(requestID) || version != auth.ProtocolVersion || s.device.ValidatePublicKey(key) != nil {
		return auth.Challenge{}, d.ErrInvalidInput
	}
	id, err := s.device.NewID()
	if err != nil {
		return auth.Challenge{}, d.ErrUnavailable
	}
	placeholder, err := s.device.NewID()
	if err != nil {
		return auth.Challenge{}, d.ErrUnavailable
	}
	challenge, err := s.device.RandomBytes(32)
	if err != nil {
		return auth.Challenge{}, d.ErrUnavailable
	}
	fingerprint, err := s.device.Fingerprint(key)
	if err != nil {
		return auth.Challenge{}, d.ErrInvalidInput
	}
	tag, err := s.protocol.LoginRequestMAC(requestID, address, key)
	if err != nil {
		return auth.Challenge{}, err
	}
	addressKey := s.budget.Key(address)
	if err = s.quota.OwnerRequest(ctx, addressKey, now); err != nil {
		return auth.Challenge{}, err
	}
	o, err := s.repo.BeginLogin(ctx, p.Login{OperationID: id, RequestID: requestID, Email: address, AddressKey: addressKey, AuthID: placeholder, ServiceID: s.protocol.ServiceID(), KeyID: s.protocol.KeyID(), Status: auth.Pending, AccountRevision: 1, PasswordRevision: 1, RoleRevision: 1, PublicKey: append([]byte(nil), key...), Fingerprint: fingerprint, Challenge: challenge, RequestMAC: tag, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), RetainUntil: now.Add(24 * time.Hour)}, now)
	if err != nil {
		return auth.Challenge{}, err
	}
	payload, err := s.protocol.LoginPayload(o.OperationID, o.Email, o.PublicKey, o.Challenge, o.ExpiresAt)
	if err != nil {
		return auth.Challenge{}, d.ErrUnavailable
	}
	return auth.Challenge{OperationID: o.OperationID, ProtocolVersion: p.LoginProtocolVersion, Challenge: o.Challenge, SigningPayload: payload, ExpiresAt: o.ExpiresAt}, nil
}
func (s *LoginService) Complete(ctx context.Context, id, password string, signature []byte, source string) (auth.Established, error) {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, source, "", now); err != nil {
		return auth.Established{}, err
	}
	if !d.ValidOperationID(id) || len(signature) < 8 || len(signature) > 72 {
		return auth.Established{}, d.ErrInvalidInput
	}
	if _, err := s.engine.Normalize(password); err != nil {
		return auth.Established{}, err
	}
	snapshot, err := s.repo.ReadLogin(ctx, id, now)
	if err != nil {
		return auth.Established{}, err
	}
	o := snapshot.Operation
	owner := o.AddressKey
	if o.Acceptable {
		owner = o.AuthID
	}
	if err = s.quota.OwnerRequest(ctx, owner, now); err != nil {
		return auth.Established{}, err
	}
	payload, err := s.protocol.LoginPayload(o.OperationID, o.Email, o.PublicKey, o.Challenge, o.ExpiresAt)
	if err != nil {
		return auth.Established{}, d.ErrUnavailable
	}
	material := s.dummy
	if snapshot.Usable {
		material = snapshot.Password.Material
	}
	upgrade := snapshot.Usable && s.engine.NeedsUpgrade(material)
	units := 1
	if upgrade {
		units = 2
	}
	if err = s.quota.Work(ctx, source, owner, units, now); err != nil {
		return auth.Established{}, err
	}
	// Both checks run for real and placeholder accounts. No signature-only
	// shortcut turns Begin into an account-existence or cheap password oracle.
	matched, err := s.engine.Verify(ctx, password, material)
	if err != nil {
		return auth.Established{}, err
	}
	proofOK := s.device.Verify(o.PublicKey, payload, signature)
	if !matched || !proofOK || !snapshot.Usable {
		if err = s.repo.FailLogin(ctx, id, s.now().UTC().Truncate(time.Millisecond)); err != nil {
			return auth.Established{}, err
		}
		return auth.Established{}, d.ErrAuthentication
	}
	var rehash d.Material
	if upgrade {
		rehash, err = s.engine.Rehash(ctx, password)
		if err != nil {
			return auth.Established{}, err
		}
	}
	credentialID, err := s.device.NewID()
	if err != nil {
		return auth.Established{}, d.ErrUnavailable
	}
	sessionID, err := s.device.NewID()
	if err != nil {
		return auth.Established{}, d.ErrUnavailable
	}
	token, digest, err := s.device.NewSessionToken()
	if err != nil {
		return auth.Established{}, d.ErrUnavailable
	}
	now = s.now().UTC().Truncate(time.Millisecond)
	credential := auth.Credential{CredentialID: credentialID, AuthID: o.AuthID, ProtocolVersion: auth.ProtocolVersion, PublicKey: o.PublicKey, Fingerprint: o.Fingerprint, CredentialRevision: o.AccountRevision, CreatedAt: now}
	session := auth.Session{SessionID: sessionID, AuthID: o.AuthID, CredentialID: credentialID, AuthenticationMethod: d.PasswordAndDevice, AccountRevision: o.AccountRevision, PasswordRevision: o.PasswordRevision, TokenDigest: digest, AuthenticatedAt: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(s.ttl)}
	credentialID, err = s.repo.CompleteLogin(ctx, p.LoginCommit{Snapshot: snapshot, Credential: credential, Session: session, Upgrade: rehash}, now)
	if err != nil {
		return auth.Established{}, err
	}
	return auth.Established{AuthID: o.AuthID, CredentialID: credentialID, SessionID: sessionID, SessionToken: token, ExpiresAt: session.ExpiresAt}, nil
}
