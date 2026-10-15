package usecase

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"time"

	auth "iwut-auth-center/internal/authentication/domain"
	authport "iwut-auth-center/internal/authentication/port"
	campus "iwut-auth-center/internal/campuscertification/domain"
	d "iwut-auth-center/internal/emailaccount/domain"
	p "iwut-auth-center/internal/emailaccount/port"
	email "iwut-auth-center/internal/emailbinding/domain"
	pwd "iwut-auth-center/internal/password/domain"
	pwdport "iwut-auth-center/internal/password/port"
	reg "iwut-auth-center/internal/registration/port"
)

type Service struct {
	repository p.Repository
	protocol   p.Protocol
	device     authport.DeviceProtocol
	engine     pwdport.Engine
	quota      pwdport.Quota
	sender     p.Sender
	serviceID  string
	ttl        time.Duration
	now        func() time.Time
}

func New(r p.Repository, protocol p.Protocol, device authport.DeviceProtocol, engine pwdport.Engine, quota pwdport.Quota, sender p.Sender, serviceID string, ttl time.Duration) (*Service, error) {
	if r == nil || protocol == nil || device == nil || engine == nil || quota == nil || sender == nil || serviceID == "" || ttl <= 0 {
		return nil, d.ErrUnavailable
	}
	return &Service{r, protocol, device, engine, quota, sender, serviceID, ttl, time.Now}, nil
}
func (s *Service) CheckOwn(ctx context.Context, token string, password bool, source string) (p.Snapshot, error) {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, source, "", now); err != nil {
		return p.Snapshot{}, err
	}
	digest, err := s.device.TokenDigest(token)
	if err != nil {
		return p.Snapshot{}, d.ErrSession
	}
	snapshot, err := s.repository.Snapshot(ctx, digest, password, now)
	if err != nil {
		return p.Snapshot{}, err
	}
	if err = s.quota.OwnerRequest(ctx, snapshot.Session.AuthID, now); err != nil {
		return p.Snapshot{}, err
	}
	return snapshot, nil
}
func (s *Service) Own(ctx context.Context, token, source string) (d.Directory, error) {
	v, err := s.CheckOwn(ctx, token, false, source)
	return v.Directory, err
}

type Started struct {
	Operation      p.Operation
	SigningPayload []byte
}

// Legacy campus routes are aliases of ADD, not an independent fact writer.
func (s *Service) BeginCampus(ctx context.Context, token, requestID, address, source string) (Started, error) {
	normalized, err := email.NormalizeEmail(address)
	if err != nil || !campus.IsWHUTEmail(normalized) {
		return Started{}, d.ErrInvalid
	}
	directory, err := s.Own(ctx, token, source)
	if err != nil {
		return Started{}, err
	}
	return s.Begin(ctx, token, d.Begin{RequestID: requestID, Email: normalized, ExpectedDirectoryRevision: directory.Revision, Source: source}, false)
}
func (s *Service) CompleteCampus(ctx context.Context, token, id, code, source string) (d.Directory, error) {
	if _, err := s.CheckOwn(ctx, token, false, source); err != nil {
		return d.Directory{}, err
	}
	if !s.protocol.ValidID(id) {
		return d.Directory{}, d.ErrInvalid
	}
	operation, err := s.repository.Get(ctx, id)
	if err != nil {
		return d.Directory{}, err
	}
	if operation.Purpose != d.Add || !campus.IsWHUTEmail(operation.Email) {
		return d.Directory{}, d.ErrVerification
	}
	result, err := s.Complete(ctx, token, id, code, "", nil, false, source)
	return result.Directory, err
}

func (s *Service) Begin(ctx context.Context, token string, b d.Begin, registration bool) (Started, error) {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, b.Source, "", now); err != nil {
		return Started{}, err
	}
	address, err := email.NormalizeEmail(b.Email)
	if err != nil || !s.protocol.ValidID(b.RequestID) {
		return Started{}, d.ErrInvalid
	}
	id, err := s.device.NewID()
	if err != nil {
		return Started{}, d.ErrUnavailable
	}
	o := p.Operation{OperationID: id, RequestID: b.RequestID, Email: address, ServiceID: s.serviceID, KeyID: s.protocol.KeyID(), Status: auth.Pending, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), ResendAfter: now.Add(time.Minute), RetainUntil: now.Add(24 * time.Hour)}
	var digest []byte
	if registration {
		if token != "" || b.DeviceVersion != auth.ProtocolVersion || b.ExpectedDirectoryRevision != 0 {
			return Started{}, d.ErrInvalid
		}
		fp, err := s.device.Fingerprint(b.PublicKey)
		if err != nil {
			return Started{}, d.ErrInvalid
		}
		challenge, err := s.device.RandomBytes(32)
		if err != nil {
			return Started{}, d.ErrUnavailable
		}
		o.Purpose = d.Register
		o.PublicKey = b.PublicKey
		o.Fingerprint = fp
		o.Actor = hex.EncodeToString(fp)
		o.Challenge = challenge
	} else {
		if b.ExpectedDirectoryRevision <= 0 || len(b.PublicKey) != 0 || b.DeviceVersion != "" {
			return Started{}, d.ErrInvalid
		}
		digest, err = s.device.TokenDigest(token)
		if err != nil {
			return Started{}, d.ErrSession
		}
		v, err := s.repository.Snapshot(ctx, digest, false, now)
		if err != nil {
			return Started{}, err
		}
		if err = s.quota.OwnerRequest(ctx, v.Session.AuthID, now); err != nil {
			return Started{}, err
		}
		o.Purpose = d.Add
		o.Actor = v.Session.AuthID
		o.AuthID = v.Session.AuthID
		o.AccountRevision = v.Session.AccountRevision
		o.DirectoryRevision = b.ExpectedDirectoryRevision
	}
	o.RequestMAC, err = s.protocol.RequestMAC(o)
	if err != nil {
		return Started{}, err
	}
	code, err := s.protocol.NewCode()
	if err != nil {
		return Started{}, err
	}
	o.CodeMAC, err = s.protocol.CodeMAC(o, code)
	if err != nil {
		return Started{}, err
	}
	o, fresh, err := s.repository.Begin(ctx, o, digest, b.Source, now)
	if err != nil {
		return Started{}, err
	}
	var payload []byte
	if registration {
		payload, err = s.protocol.Payload(o)
		if err != nil {
			return Started{}, d.ErrUnavailable
		}
	}
	if fresh {
		if err = s.sender.Send(ctx, o.Email, o.Purpose, code, o.ExpiresAt); err != nil {
			return Started{}, d.ErrDelivery
		}
	}
	return Started{Operation: o, SigningPayload: payload}, nil
}

type Completed struct {
	OperationID  string
	Directory    d.Directory
	Registration *auth.Established
}

func (s *Service) Complete(ctx context.Context, token, id, code, password string, signature []byte, registration bool, source string) (Completed, error) {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, source, "", now); err != nil {
		return Completed{}, err
	}
	if !s.protocol.ValidID(id) || !email.ValidCode(code) {
		return Completed{}, d.ErrInvalid
	}
	var digest []byte
	var caller p.Snapshot
	var err error
	if registration {
		if token != "" || password == "" || len(signature) == 0 {
			return Completed{}, d.ErrInvalid
		}
	} else {
		if password != "" || len(signature) != 0 {
			return Completed{}, d.ErrInvalid
		}
		digest, err = s.device.TokenDigest(token)
		if err != nil {
			return Completed{}, d.ErrSession
		}
		caller, err = s.repository.Snapshot(ctx, digest, false, now)
		if err != nil {
			return Completed{}, err
		}
		if err = s.quota.OwnerRequest(ctx, caller.Session.AuthID, now); err != nil {
			return Completed{}, err
		}
	}
	o, err := s.repository.Get(ctx, id)
	if err != nil {
		return Completed{}, err
	}
	if (registration && o.Purpose != d.Register) || (!registration && (o.Purpose != d.Add || o.AuthID != caller.Session.AuthID)) {
		return Completed{}, d.ErrVerification
	}
	if o.Status == auth.Completed && registration {
		return Completed{}, d.ErrCompleted
	}
	if o.KeyID != s.protocol.KeyID() || o.FailedAttempts >= 5 || !now.Before(o.RetainUntil) || (o.Status != auth.Completed && (!now.Before(o.ExpiresAt) || o.Status != auth.Pending)) {
		return Completed{}, d.ErrVerification
	}
	codeMAC, err := s.protocol.CodeMAC(o, code)
	valid := err == nil && hmac.Equal(o.CodeMAC, codeMAC)
	if registration {
		payload, err := s.protocol.Payload(o)
		valid = valid && err == nil && s.device.Verify(o.PublicKey, payload, signature)
	}
	if !valid {
		if err = s.repository.Fail(ctx, id, now); err != nil {
			return Completed{}, err
		}
		return Completed{}, d.ErrVerification
	}
	bindingID, err := s.device.NewID()
	if err != nil {
		return Completed{}, d.ErrUnavailable
	}
	var candidate *p.Registration
	var established *auth.Established
	if registration {
		if _, err = s.engine.ValidateNew(password); err != nil {
			return Completed{}, err
		}
		if err = s.quota.Work(ctx, source, s.protocol.AddressQuotaKey(o.Email), 1, now); err != nil {
			return Completed{}, err
		}
		material, err := s.engine.Hash(ctx, password)
		if err != nil {
			return Completed{}, err
		}
		owner, err := s.device.NewID()
		if err != nil {
			return Completed{}, d.ErrUnavailable
		}
		credentialID, err := s.device.NewID()
		if err != nil {
			return Completed{}, d.ErrUnavailable
		}
		sessionID, err := s.device.NewID()
		if err != nil {
			return Completed{}, d.ErrUnavailable
		}
		newToken, tokenDigest, err := s.device.NewSessionToken()
		if err != nil {
			return Completed{}, d.ErrUnavailable
		}
		now = s.now().UTC().Truncate(time.Millisecond)
		credential := auth.Credential{CredentialRevision: 1, CredentialID: credentialID, AuthID: owner, ProtocolVersion: auth.ProtocolVersion, PublicKey: o.PublicKey, Fingerprint: o.Fingerprint, CreatedAt: now}
		session := auth.Session{AccountRevision: 1, SessionID: sessionID, AuthID: owner, CredentialID: credentialID, AuthenticationMethod: "DEVICE_CREDENTIAL", TokenDigest: tokenDigest, AuthenticatedAt: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(s.ttl)}
		candidate = &p.Registration{Commit: reg.RegistrationCommit{Credential: credential, Session: session}, Password: material, BindingID: bindingID}
		established = &auth.Established{AuthID: owner, CredentialID: credentialID, SessionID: sessionID, SessionToken: newToken, ExpiresAt: session.ExpiresAt}
	}
	directory, err := s.repository.Complete(ctx, o, digest, candidate, bindingID, now)
	if err != nil {
		return Completed{}, err
	}
	return Completed{OperationID: id, Directory: directory, Registration: established}, nil
}

func (s *Service) Mutate(ctx context.Context, token string, b d.Mutation, switchRole bool) (string, d.Directory, error) {
	if !s.protocol.ValidID(b.RequestID) || !s.protocol.ValidID(b.BindingID) || b.ExpectedDirectoryRevision <= 0 {
		return "", d.Directory{}, d.ErrInvalid
	}
	v, err := s.CheckOwn(ctx, token, switchRole, b.Source)
	if err != nil {
		return "", d.Directory{}, err
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	purpose := d.Remove
	normalized := ""
	if switchRole {
		purpose = d.Switch
		if b.ExpectedLoginRoleRevision <= 0 {
			return "", d.Directory{}, d.ErrInvalid
		}
		normalized, err = s.engine.Normalize(b.Password)
		if err != nil {
			return "", d.Directory{}, err
		}
	} else if b.Password != "" || b.ExpectedLoginRoleRevision != 0 {
		return "", d.Directory{}, d.ErrInvalid
	}
	o := p.Mutation{AuthID: v.Session.AuthID, Purpose: purpose, RequestID: b.RequestID, BindingID: b.BindingID, DirectoryRevision: b.ExpectedDirectoryRevision, RoleRevision: b.ExpectedLoginRoleRevision, AccountRevision: v.Session.AccountRevision, KeyID: s.protocol.MutationKeyID(purpose), CreatedAt: now, RetainUntil: now.Add(24 * time.Hour)}
	if switchRole {
		o.PasswordRevision = v.Password.Revision
	}
	prior, found, err := s.repository.FindMutation(ctx, v.Session.TokenDigest, purpose, b.RequestID, now)
	if err != nil {
		return "", d.Directory{}, err
	}
	if found {
		if prior.KeyID != o.KeyID || prior.BindingID != o.BindingID || prior.DirectoryRevision != o.DirectoryRevision || prior.RoleRevision != o.RoleRevision {
			return "", d.Directory{}, d.ErrConflict
		}
		o = prior
	}
	o.RequestMAC, err = s.protocol.MutationMAC(o, normalized)
	if err != nil {
		return "", d.Directory{}, err
	}
	if found && !hmac.Equal(o.RequestMAC, prior.RequestMAC) {
		return "", d.Directory{}, d.ErrConflict
	}
	if switchRole {
		if err = s.quota.Work(ctx, b.Source, v.Session.AuthID, 1, now); err != nil {
			return "", d.Directory{}, err
		}
		ok, err := s.engine.Verify(ctx, b.Password, v.Password.Material)
		if err != nil {
			return "", d.Directory{}, err
		}
		if !ok {
			return "", d.Directory{}, pwd.ErrAuthentication
		}
	}
	if !found {
		o.OperationID, err = s.device.NewID()
		if err != nil {
			return "", d.Directory{}, d.ErrUnavailable
		}
	}
	result, err := s.repository.Mutate(ctx, v, o, now)
	return o.OperationID, result, err
}
