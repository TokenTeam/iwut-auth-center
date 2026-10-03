package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
)

func (s *Service) access(ctx context.Context, tx port.Tx, raw string) (d.Access, d.Family, d.Runtime, d.Grant, []string, error) {
	var a d.Access
	var f d.Family
	var rt d.Runtime
	var g d.Grant
	if !s.crypto.ValidOpaque(raw) {
		return a, f, rt, g, nil, d.ErrToken
	}
	a, err := tx.Access(s.crypto.Digest("access", raw))
	if err != nil {
		if missing(err) {
			err = d.ErrToken
		}
		return a, f, rt, g, nil, err
	}
	if a.Revoked || !a.ExpiresAt.After(s.now()) {
		return a, f, rt, g, nil, d.ErrToken
	}
	f, err = tx.Family(a.FamilyID)
	if err != nil {
		if !missing(err) {
			return a, f, rt, g, nil, err
		}
		return a, f, rt, g, nil, d.ErrToken
	}
	if a.AuthID != f.AuthID || a.GrantID != f.GrantID || a.GrantEpoch != f.GrantEpoch || a.ClientEpoch != f.ClientEpoch || a.Runtime.Client.ID != f.ClientID || a.Runtime.Client.ApplicationID != f.ApplicationID || a.Runtime.Client.Channel != f.Channel || a.Runtime.Major != f.Major || a.Runtime.TesterID != f.TesterID {
		return a, f, rt, g, nil, d.ErrToken
	}
	rt, g, c, err := s.current(ctx, tx, f)
	if err != nil {
		if !errors.Is(err, d.ErrUnavailable) {
			err = d.ErrToken
		}
		return a, f, rt, g, nil, err
	}
	effective := d.Intersect(a.Scopes, g.Scopes, d.Union(rt.Required, rt.Optional), c.Enabled(s.cfg.RefreshEnabled))
	return a, f, rt, g, effective, nil
}
func (s *Service) UserInfo(ctx context.Context, raw string) (d.UserInfo, error) {
	var out d.UserInfo
	err := s.transaction(ctx, func(tx port.Tx) error {
		out = d.UserInfo{}
		a, f, rt, _, scopes, err := s.access(ctx, tx, raw)
		if err != nil {
			return err
		}
		if !d.Contains(a.Audiences, s.cfg.Issuer+"/userinfo") || !d.Contains(scopes, "openid") {
			return d.ErrInsufficient
		}
		sector, err := tx.Sector(f.ApplicationID)
		if err != nil {
			return d.ErrUnavailable
		}
		subject, err := tx.Subject(f.AuthID, sector.ID)
		if err != nil || subject.ID == "" || subject.AuthID != f.AuthID || subject.SectorID != sector.ID {
			return d.ErrUnavailable
		}
		out.Subject = subject.ID
		if d.Contains(scopes, "email") {
			user, err := tx.User(f.AuthID)
			if err != nil {
				return err
			}
			if user.EmailVerified {
				out.Email = user.Email
				out.EmailVerified = true
			}
		}
		return s.fresh(rt)
	})
	if err != nil {
		return d.UserInfo{}, err
	}
	return out, nil
}
