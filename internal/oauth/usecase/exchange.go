package usecase

import (
	"context"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
	"time"
)

func (s *Service) clientProof(ctx context.Context, p d.ClientProof) (d.Client, error) {
	cl, err := s.app.Client(ctx, p.ClientID)
	if err != nil {
		return cl, err
	}
	if cl.Type == "PUBLIC_PKCE" {
		if p.Basic || p.Secret != "" {
			return cl, d.ErrClient
		}
		return cl, nil
	}
	if !p.Basic || p.Secret == "" {
		return cl, d.ErrClient
	}
	ok, err := s.app.VerifySecret(ctx, cl, p.Secret)
	if err != nil {
		return cl, err
	}
	if !ok {
		return cl, d.ErrClient
	}
	return cl, nil
}
func (s *Service) Exchange(ctx context.Context, proof d.ClientProof, raw, redirect, verifier string) (d.TokenResponse, error) {
	var out d.TokenResponse
	client, err := s.clientProof(ctx, proof)
	if err != nil {
		return out, err
	}
	if !s.crypto.ValidOpaque(raw) {
		return out, d.ErrGrant
	}
	var resultErr error
	err = s.transaction(ctx, func(tx port.Tx) error {
		out = d.TokenResponse{}
		resultErr = nil
		code, err := tx.Code(s.crypto.Digest("code", raw))
		if missing(err) {
			return d.ErrGrant
		}
		if err != nil {
			return err
		}
		if code.ClientID != client.ID || code.Runtime.Client.ApplicationID != client.ApplicationID || code.RedirectURI != redirect || code.Challenge != "" && !s.crypto.VerifyPKCE(code.Challenge, verifier) || code.Challenge == "" && verifier != "" || client.Type == "PUBLIC_PKCE" && code.Challenge == "" {
			return d.ErrGrant
		}
		if code.Consumed {
			// Proof must succeed before a replay is allowed to revoke a family.
			f, e := tx.Family(code.FamilyID)
			if e != nil {
				return d.ErrGrant
			}
			f.Revoked = true
			if e = tx.SaveFamily(f); e != nil {
				return e
			}
			resultErr = d.ErrGrant
			return nil
		}
		if !code.ExpiresAt.After(s.now()) || code.Runtime.Client.AuthorizationEpoch != client.AuthorizationEpoch || code.Runtime.Client.RegistrationRevision != client.RegistrationRevision {
			return d.ErrGrant
		}
		rt, err := s.app.Authorize(ctx, code.Runtime, code.AuthID)
		if err != nil {
			return err
		}
		if !code.Runtime.SameTuple(rt) {
			return d.ErrGrant
		}
		if _, err = s.user(tx, code.AuthID, rt); err != nil {
			return err
		}
		g, err := tx.Grant(code.GrantID)
		if err != nil {
			return err
		}
		if !grantMatches(g, code.AuthID, client.ApplicationID, client.Channel, code.GrantEpoch) || !d.Subset(code.Scopes, g.Scopes) {
			return d.ErrGrant
		}
		if _, err = s.checkScopes(tx, rt, code.Scopes); err != nil {
			return err
		}
		sector, err := tx.Sector(client.ApplicationID)
		if err != nil {
			return d.ErrUnavailable
		}
		subject, err := tx.Subject(code.AuthID, sector.ID)
		if missing(err) {
			subject = d.Subject{ID: s.crypto.ID(), AuthID: code.AuthID, SectorID: sector.ID}
			if err = tx.SaveSubject(subject); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		now := s.now()
		offline := d.Contains(code.Scopes, "offline_access")
		if offline && !s.cfg.RefreshEnabled {
			return d.ErrGrant
		}
		f := d.Family{ID: s.crypto.ID(), AuthID: code.AuthID, ClientID: client.ID, ApplicationID: client.ApplicationID, GrantID: g.ID, Channel: client.Channel, TesterID: rt.TesterID, Major: rt.Major, GrantEpoch: g.RevocationEpoch, ClientEpoch: client.AuthorizationEpoch, ScopeCeiling: code.Scopes, CreatedAt: now, IdleExpiresAt: now.Add(s.cfg.AccessTTL), AbsoluteExpiresAt: now.Add(s.cfg.AccessTTL)}
		if offline {
			f.IdleExpiresAt = now.Add(s.cfg.IdleTTL)
			f.AbsoluteExpiresAt = now.Add(s.cfg.AbsoluteTTL)
		}
		if err = tx.SaveFamily(f); err != nil {
			return err
		}
		out, err = s.issue(tx, f, g, rt, code.Scopes, offline)
		if err != nil {
			return err
		}
		out.IDToken, err = s.crypto.SignID(map[string]any{"iss": s.cfg.Issuer, "sub": subject.ID, "aud": client.ID, "iat": now.Unix(), "exp": now.Add(s.cfg.IDTTL).Unix(), "auth_time": code.AuthenticatedAt.Unix(), "nonce": code.Nonce, "at_hash": s.crypto.AccessHash(out.AccessToken)})
		if err != nil {
			return err
		}
		code.Consumed = true
		code.FamilyID = f.ID
		if err = tx.SaveCode(code); err != nil {
			return err
		}
		if err = s.audit(tx, g, client.ID, "CODE_EXCHANGED", code.Scopes); err != nil {
			return err
		}
		return s.fresh(rt)
	})
	if err != nil {
		return d.TokenResponse{}, err
	}
	if resultErr != nil {
		return d.TokenResponse{}, resultErr
	}
	return out, nil
}
func grantMatches(g d.Grant, auth, app, channel string, epoch int64) bool {
	return g.ID != "" && g.AuthID == auth && g.ApplicationID == app && g.Channel == channel && g.Status == "ACTIVE" && g.RevocationEpoch == epoch && g.Revision > 0
}
func (s *Service) issue(tx port.Tx, f d.Family, g d.Grant, rt d.Runtime, scopes []string, refresh bool) (d.TokenResponse, error) {
	var out d.TokenResponse
	raw, err := s.crypto.Random()
	if err != nil {
		return out, d.ErrUnavailable
	}
	catalog, err := s.catalog(tx)
	if err != nil {
		return out, err
	}
	aud := []string{}
	for _, scope := range catalog.Scopes {
		if d.Contains(scopes, scope.Name) && scope.Enabled {
			if scope.Name == "openid" || scope.Name == "email" {
				aud = append(aud, s.cfg.Issuer+"/userinfo")
			}
			if scope.Kind == "RESOURCE" && scope.Audience != "" {
				aud = append(aud, scope.Audience)
			}
		}
	}
	now := s.now()
	expiry := earliest(now.Add(s.cfg.AccessTTL), f.IdleExpiresAt, f.AbsoluteExpiresAt)
	if !expiry.After(now) {
		return out, d.ErrGrant
	}
	if err = tx.SaveAccess(d.Access{ID: s.crypto.ID(), AuthID: f.AuthID, GrantID: g.ID, GrantRevision: g.Revision, GrantEpoch: f.GrantEpoch, ClientEpoch: f.ClientEpoch, Runtime: rt, IssuedAt: now, Digest: s.crypto.Digest("access", raw), FamilyID: f.ID, Scopes: d.Union(scopes), Audiences: d.Union(aud), ExpiresAt: expiry}); err != nil {
		return out, err
	}
	out = d.TokenResponse{AccessToken: raw, ExpiresIn: int64(expiry.Sub(now) / time.Second), Scopes: d.Union(scopes)}
	if refresh {
		raw, err = s.crypto.Random()
		if err != nil {
			return d.TokenResponse{}, d.ErrUnavailable
		}
		if err = tx.SaveRefresh(d.Refresh{Digest: s.crypto.Digest("refresh", raw), FamilyID: f.ID}); err != nil {
			return d.TokenResponse{}, err
		}
		out.RefreshToken = raw
	}
	return out, nil
}
func earliest(first time.Time, rest ...time.Time) time.Time {
	for _, v := range rest {
		if v.Before(first) {
			first = v
		}
	}
	return first
}
func (s *Service) JWKS() any { return s.crypto.JWKS() }
func (s *Service) Discovery(ctx context.Context) (map[string]any, error) {
	var scopes []string
	err := s.transaction(ctx, func(tx port.Tx) error {
		c, e := s.catalog(tx)
		if e != nil {
			return e
		}
		scopes = c.Enabled(s.cfg.RefreshEnabled)
		return nil
	})
	if err != nil {
		return nil, err
	}
	grants := []string{"authorization_code"}
	if s.cfg.RefreshEnabled {
		grants = append(grants, "refresh_token")
	}
	return map[string]any{"issuer": s.cfg.Issuer, "authorization_endpoint": s.cfg.Issuer + "/authorize", "token_endpoint": s.cfg.Issuer + "/token", "userinfo_endpoint": s.cfg.Issuer + "/userinfo", "revocation_endpoint": s.cfg.Issuer + "/revoke", "jwks_uri": s.cfg.Issuer + "/jwks", "response_types_supported": []string{"code"}, "response_modes_supported": []string{"query"}, "revocation_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "grant_types_supported": grants, "subject_types_supported": []string{"pairwise"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "code_challenge_methods_supported": []string{"S256"}, "scopes_supported": scopes, "claims_supported": []string{"iss", "sub", "aud", "iat", "exp", "auth_time", "nonce", "at_hash", "email", "email_verified"}, "authorization_response_iss_parameter_supported": true}, nil
}
