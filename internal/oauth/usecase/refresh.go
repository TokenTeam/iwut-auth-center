package usecase

import (
	"context"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
)

func (s *Service) current(ctx context.Context, tx port.Tx, f d.Family) (d.Runtime, d.Grant, d.Catalog, error) {
	var rt d.Runtime
	var g d.Grant
	var c d.Catalog
	if f.Revoked || !f.IdleExpiresAt.After(s.now()) || !f.AbsoluteExpiresAt.After(s.now()) || f.GrantEpoch < 1 || f.ClientEpoch < 1 {
		return rt, g, c, d.ErrGrant
	}
	user, e := tx.User(f.AuthID)
	if e != nil {
		return rt, g, c, e
	}
	if f.AccountRevision <= 0 || f.AccountRevision != user.AccountRevision {
		return rt, g, c, d.ErrGrant
	}
	client, err := s.app.Client(ctx, f.ClientID)
	if err != nil {
		return rt, g, c, err
	}
	if client.ApplicationID != f.ApplicationID || client.Channel != f.Channel || client.AuthorizationEpoch != f.ClientEpoch {
		return rt, g, c, d.ErrGrant
	}
	rt, err = s.app.Runtime(ctx, client, f.Major)
	if err != nil {
		return rt, g, c, err
	}
	rt, err = s.app.Authorize(ctx, rt, f.AuthID)
	if err != nil {
		return rt, g, c, err
	}
	if rt.TesterID != f.TesterID {
		return rt, g, c, d.ErrGrant
	}
	if _, err = s.user(tx, f.AuthID, rt); err != nil {
		return rt, g, c, err
	}
	g, err = tx.Grant(f.GrantID)
	if err != nil {
		return rt, g, c, err
	}
	if !grantMatches(g, f.AuthID, f.ApplicationID, f.Channel, f.GrantEpoch) {
		return rt, g, c, d.ErrGrant
	}
	c, err = s.catalog(tx)
	return rt, g, c, err
}
func (s *Service) Refresh(ctx context.Context, proof d.ClientProof, raw string, requested []string) (d.TokenResponse, error) {
	var out d.TokenResponse
	if !s.cfg.RefreshEnabled {
		return out, d.ErrGrant
	}
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
		r, err := tx.Refresh(s.crypto.Digest("refresh", raw))
		if missing(err) {
			return d.ErrGrant
		}
		if err != nil {
			return err
		}
		f, err := tx.Family(r.FamilyID)
		if err != nil {
			return err
		}
		if f.ClientID != client.ID || f.ApplicationID != client.ApplicationID || f.Channel != client.Channel {
			return d.ErrGrant
		}
		user, e := tx.User(f.AuthID)
		if e != nil {
			return e
		}
		if f.AccountRevision <= 0 || f.AccountRevision != user.AccountRevision {
			return d.ErrGrant
		}
		if r.Consumed {
			f.Revoked = true
			if err = tx.SaveFamily(f); err != nil {
				return err
			}
			resultErr = d.ErrGrant
			return nil
		}
		rt, g, c, err := s.current(ctx, tx, f)
		if err != nil {
			return err
		}
		if rt.Client.CredentialRevision != client.CredentialRevision {
			return d.ErrClient
		}
		q := requested
		if q == nil {
			q = f.ScopeCeiling
		}
		if !d.ValidScopes(q) || !d.Subset(q, f.ScopeCeiling) || !d.Contains(q, "openid") || !d.Contains(q, "offline_access") {
			return d.ErrScope
		}
		effective := d.Intersect(q, g.Scopes, d.Union(rt.Required, rt.Optional), c.Enabled(s.cfg.RefreshEnabled))
		if !d.Contains(effective, "openid") || !d.Contains(effective, "offline_access") {
			return d.ErrGrant
		}
		now := s.now()
		f.ScopeCeiling = d.Union(q)
		f.IdleExpiresAt = earliest(now.Add(s.cfg.IdleTTL), f.AbsoluteExpiresAt)
		f.LastRefreshedAt = &now
		r.Consumed = true
		if err = tx.SaveRefresh(r); err != nil {
			return err
		}
		if err = tx.SaveFamily(f); err != nil {
			return err
		}
		out, err = s.issue(tx, f, g, rt, effective, true)
		if err != nil {
			return err
		}
		if err = s.audit(tx, g, f.ClientID, "REFRESHED", effective); err != nil {
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
