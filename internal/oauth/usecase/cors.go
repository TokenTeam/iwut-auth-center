package usecase

import (
	"context"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
	"net/url"
)

// The deployment lists public client/major references, never trusted origins.
// Every preflight and response resolves their current approved runtime again.
func (s *Service) PublicOrigin(ctx context.Context, clientID string, major int32, origin string) (bool, error) {
	c, e := s.app.Client(ctx, clientID)
	if e != nil {
		return false, e
	}
	if c.Type != "PUBLIC_PKCE" {
		return false, nil
	}
	rt, e := s.app.Runtime(ctx, c, major)
	if e != nil {
		return false, e
	}
	e = s.transaction(ctx, func(tx port.Tx) error { return applicationOpen(tx, c.ApplicationID) })
	if e != nil {
		return false, e
	}
	for _, uri := range rt.Redirects {
		u, e := url.Parse(uri)
		if e == nil && u.Scheme+"://"+u.Host == origin {
			return true, nil
		}
	}
	return false, nil
}
func (s *Service) AccessClient(ctx context.Context, raw string) (string, error) {
	var id string
	if !s.crypto.ValidOpaque(raw) {
		return "", d.ErrToken
	}
	e := s.transaction(ctx, func(tx port.Tx) error {
		a, e := tx.Access(s.crypto.Digest("access", raw))
		if e != nil {
			if missing(e) {
				return d.ErrToken
			}
			return e
		}
		f, e := tx.Family(a.FamilyID)
		if e != nil {
			if missing(e) {
				return d.ErrToken
			}
			return e
		}
		if e = applicationOpen(tx, f.ApplicationID); e != nil {
			return d.ErrToken
		}
		id = f.ClientID
		return nil
	})
	return id, e
}

func (s *Service) AllowOrigin(ctx context.Context, client, origin string) (bool, error) {
	var references []d.Registration
	e := s.transaction(ctx, func(tx port.Tx) error { var err error; references, err = tx.Registrations(origin, client); return err })
	if e != nil {
		return false, e
	}
	for _, ref := range references {
		allowed, e := s.PublicOrigin(ctx, ref.ClientID, ref.Major, origin)
		if e == d.ErrUnavailable {
			return false, e
		}
		if e == nil && allowed {
			return true, nil
		}
	}
	return false, nil
}
