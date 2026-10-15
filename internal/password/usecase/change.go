package usecase

import (
	"context"
	"crypto/hmac"
	"time"

	auth "iwut-auth-center/internal/authentication/domain"
	authport "iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/password/domain"
	"iwut-auth-center/internal/password/port"
)

type ChangeService struct {
	repository port.ChangeRepository
	engine     port.Engine
	protocol   port.ChangeProtocol
	device     authport.DeviceProtocol
	quota      port.Quota
	ttl        time.Duration
	now        func() time.Time
}

func NewChangeService(r port.ChangeRepository, e port.Engine, p port.ChangeProtocol, d authport.DeviceProtocol, q port.Quota, ttl time.Duration) (*ChangeService, error) {
	if r == nil || e == nil || p == nil || d == nil || q == nil || ttl <= 0 || ttl > 365*24*time.Hour {
		return nil, domain.ErrUnavailable
	}
	return &ChangeService{r, e, p, d, q, ttl, time.Now}, nil
}

func (s *ChangeService) Change(ctx context.Context, token, requestID, current, next, source string) (string, auth.Established, error) {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, source, "", now); err != nil {
		return "", auth.Established{}, err
	}
	digest, err := s.device.TokenDigest(token)
	if err != nil {
		return "", auth.Established{}, domain.ErrSessionInvalid
	}
	snapshot, err := s.repository.ReadSnapshot(ctx, digest, now)
	if err != nil {
		return "", auth.Established{}, err
	}
	if err = s.quota.OwnerRequest(ctx, snapshot.Session.AuthID, now); err != nil {
		return "", auth.Established{}, err
	}
	// Normalize both inputs but do not retroactively apply new policy to the old
	// secret. Error responses never interpolate any of these inputs.
	oldNormalized, err := s.engine.Normalize(current)
	if err != nil {
		return "", auth.Established{}, err
	}
	newNormalized, err := s.engine.ValidateNew(next)
	if err != nil {
		return "", auth.Established{}, err
	}
	prior, found, err := s.repository.FindChange(ctx, digest, requestID, now)
	if err != nil {
		return "", auth.Established{}, err
	}
	if found {
		tag, e := s.protocol.ChangeMAC(prior.AuthID, requestID, prior.SourceSessionID, prior.OriginalAccountRevision, prior.OriginalPasswordRevision, oldNormalized, newNormalized)
		if e != nil {
			return "", auth.Established{}, e
		}
		if prior.KeyID != s.protocol.KeyID() || !hmac.Equal(tag, prior.RequestMAC) {
			return "", auth.Established{}, domain.ErrRequestConflict
		}
		return "", auth.Established{}, domain.ErrAlreadyCompleted
	}
	tag, err := s.protocol.ChangeMAC(snapshot.Session.AuthID, requestID, snapshot.Session.SessionID, snapshot.Session.AccountRevision, snapshot.Password.Revision, oldNormalized, newNormalized)
	if err != nil {
		return "", auth.Established{}, err
	}
	if err = s.quota.Work(ctx, source, snapshot.Session.AuthID, 2, now); err != nil {
		return "", auth.Established{}, err
	}
	matched, err := s.engine.Verify(ctx, current, snapshot.Password.Material)
	if err != nil {
		return "", auth.Established{}, err
	}
	if !matched {
		return "", auth.Established{}, domain.ErrAuthentication
	}
	if oldNormalized == newNormalized {
		return "", auth.Established{}, domain.ErrUnchanged
	}
	material, err := s.engine.Hash(ctx, next)
	if err != nil {
		return "", auth.Established{}, err
	}
	revision, passwordRevision, err := domain.NextRevisions(snapshot.Session.AccountRevision, snapshot.MinimumCredentialRevision, snapshot.Password.Revision)
	if err != nil {
		return "", auth.Established{}, err
	}
	operationID, err := s.device.NewID()
	if err != nil {
		return "", auth.Established{}, domain.ErrUnavailable
	}
	sessionID, err := s.device.NewID()
	if err != nil {
		return "", auth.Established{}, domain.ErrUnavailable
	}
	newToken, newDigest, err := s.device.NewSessionToken()
	if err != nil {
		return "", auth.Established{}, domain.ErrUnavailable
	}
	// Crypto may have taken time; Session lifetime begins at final preparation.
	now = s.now().UTC().Truncate(time.Millisecond)
	session := auth.Session{AccountRevision: revision, PasswordRevision: passwordRevision, SourceSessionID: snapshot.Session.SessionID, SessionID: sessionID, AuthID: snapshot.Session.AuthID, CredentialID: snapshot.Session.CredentialID, AuthenticationMethod: domain.PasswordAndSession, TokenDigest: newDigest, AuthenticatedAt: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(s.ttl)}
	op := port.Change{AuthID: session.AuthID, RequestID: requestID, OperationID: operationID, SourceSessionID: snapshot.Session.SessionID, RetainedCredentialID: session.CredentialID, KeyID: s.protocol.KeyID(), OriginalAccountRevision: snapshot.Session.AccountRevision, OriginalPasswordRevision: snapshot.Password.Revision, RequestMAC: tag, CreatedAt: now, RetainUntil: now.Add(24 * time.Hour)}
	if err = s.repository.CommitChange(ctx, port.ChangeCommit{Snapshot: snapshot, Operation: op, NewMaterial: material, Session: session}, now); err != nil {
		return "", auth.Established{}, err
	}
	return operationID, auth.Established{AuthID: session.AuthID, CredentialID: session.CredentialID, SessionID: session.SessionID, SessionToken: newToken, ExpiresAt: session.ExpiresAt}, nil
}

func (s *ChangeService) Get(ctx context.Context, token, requestID, source string) (port.Change, bool, time.Time, error) {
	now := s.now().UTC().Truncate(time.Millisecond)
	if err := s.quota.General(ctx, source, "", now); err != nil {
		return port.Change{}, false, now, err
	}
	digest, err := s.device.TokenDigest(token)
	if err != nil {
		return port.Change{}, false, now, domain.ErrSessionInvalid
	}
	snapshot, err := s.repository.ReadSnapshot(ctx, digest, now)
	if err != nil {
		return port.Change{}, false, now, err
	}
	if err = s.quota.OwnerRequest(ctx, snapshot.Session.AuthID, now); err != nil {
		return port.Change{}, false, now, err
	}
	op, found, err := s.repository.FindChange(ctx, digest, requestID, now)
	return op, found, now, err
}
