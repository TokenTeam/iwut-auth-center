package usecase

import (
	"context"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
)

func (s *Service) ListGrants(ctx context.Context, session, cursor string, limit int) ([]d.Grant, error) {
	if limit < 1 || limit > 50 {
		return nil, d.ErrRequest
	}
	var out []d.Grant
	err := s.transaction(ctx, func(tx port.Tx) error {
		ss, e := tx.Session(session, s.now())
		if e != nil {
			return e
		}
		var err error
		out, err = tx.ListGrants(ss.AuthID, cursor, limit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) RevokeGrant(ctx context.Context, session, id string, revision int64, all bool, scopes []string) (d.Grant, error) {
	var out d.Grant
	if id == "" || revision < 1 || !d.ValidScopes(scopes) || all && len(scopes) != 0 || !all && len(scopes) == 0 {
		return out, d.ErrRequest
	}
	var resultErr error
	err := s.transaction(ctx, func(tx port.Tx) error {
		out = d.Grant{}
		resultErr = nil
		ss, e := tx.Session(session, s.now())
		if e != nil {
			return e
		}
		g, e := tx.Grant(id)
		if e != nil {
			return e
		}
		if g.AuthID != ss.AuthID {
			return d.ErrNotFound
		}
		out = g
		if g.Revision != revision {
			resultErr = d.ErrConflict
			return nil
		}
		remaining := d.Difference(g.Scopes, scopes)
		if all || d.Contains(scopes, "openid") {
			remaining = []string{}
		}
		if len(remaining) == len(g.Scopes) && g.Status == "ACTIVE" || g.Status == "REVOKED" && len(remaining) == 0 {
			return nil
		}
		g.Scopes = remaining
		g.Status = "ACTIVE"
		if len(remaining) == 0 {
			g.Status = "REVOKED"
		}
		g.Revision++
		g.RevocationEpoch++
		g.UpdatedAt = s.now()
		if e = tx.SaveGrant(g); e != nil {
			return e
		}
		if e = s.audit(tx, g, "", "REVOKED", scopes); e != nil {
			return e
		}
		out = g
		return nil
	})
	if err != nil {
		return d.Grant{}, err
	}
	return out, resultErr
}
func (s *Service) RevokeToken(ctx context.Context, proof d.ClientProof, raw, hint string) error {
	if hint != "" && hint != "access_token" && hint != "refresh_token" {
		return d.ErrRequest
	}
	client, err := s.clientProof(ctx, proof)
	if err != nil {
		return err
	}
	if !s.crypto.ValidOpaque(raw) {
		return nil
	}
	return s.transaction(ctx, func(tx port.Tx) error {
		// Hints are only hints. Both kinds are checked, without a token oracle.
		a, err := tx.Access(s.crypto.Digest("access", raw))
		if err == nil {
			f, e := tx.Family(a.FamilyID)
			if e != nil {
				return d.ErrUnavailable
			}
			if f.ClientID == client.ID {
				a.Revoked = true
				return tx.SaveAccess(a)
			}
			return nil
		}
		if !missing(err) {
			return err
		}
		r, err := tx.Refresh(s.crypto.Digest("refresh", raw))
		if missing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		f, err := tx.Family(r.FamilyID)
		if err != nil {
			return err
		}
		if f.ClientID == client.ID {
			f.Revoked = true
			return tx.SaveFamily(f)
		}
		return nil
	})
}
