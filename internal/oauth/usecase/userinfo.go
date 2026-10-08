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
	if a.AccountRevision <= 0 || a.AccountRevision != f.AccountRevision || a.AuthID != f.AuthID || a.GrantID != f.GrantID || a.GrantEpoch != f.GrantEpoch || a.ClientEpoch != f.ClientEpoch || a.Runtime.Client.ID != f.ClientID || a.Runtime.Client.ApplicationID != f.ApplicationID || a.Runtime.Client.Channel != f.Channel || a.Runtime.Major != f.Major || a.Runtime.TesterID != f.TesterID {
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
		catalog, err := s.catalog(tx)
		if err != nil {
			return err
		}
		definitions := make([]d.Scope, 0)
		for _, definition := range catalog.Scopes {
			if definition.Kind == "USERINFO_PROFILE" && d.Contains(scopes, definition.Name) {
				if definition.Name != "profile."+definition.ProfileField || !d.ValidProfileValueType(definition.ProfileValueType) {
					return d.ErrUnavailable
				}
				definitions = append(definitions, definition)
			}
		}
		if len(definitions) > 0 {
			profile, err := tx.Profile(f.AuthID)
			if err != nil {
				return err
			}
			values := map[string]d.ProfileValue{}
			for _, entry := range profile.Entries {
				values[entry.Key] = entry.Value
			}
			for _, definition := range definitions {
				value, exists := values[definition.ProfileField]
				if !exists {
					continue
				}
				if value.Type != definition.ProfileValueType {
					return d.ErrUnavailable
				}
				out.Profile = append(out.Profile, d.ProfileEntry{Key: definition.ProfileField, Value: value})
			}
		}
		return s.fresh(rt)
	})
	if err != nil {
		return d.UserInfo{}, err
	}
	return out, nil
}
