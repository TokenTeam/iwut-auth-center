package usecase

import (
	"context"
	"errors"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
	"time"
)

func (s *Service) access(ctx context.Context, tx port.Tx, raw string) (d.Access, d.Family, d.Runtime, d.Grant, []string, time.Time, error) {
	var a d.Access
	var f d.Family
	var rt d.Runtime
	var g d.Grant
	if !s.crypto.ValidOpaque(raw) {
		return a, f, rt, g, nil, time.Time{}, d.ErrToken
	}
	a, err := tx.Access(s.crypto.Digest("access", raw))
	if err != nil {
		if missing(err) {
			err = d.ErrToken
		}
		return a, f, rt, g, nil, time.Time{}, err
	}
	if a.Revoked {
		return a, f, rt, g, nil, time.Time{}, d.ErrToken
	}
	f, err = tx.Family(a.FamilyID)
	if err != nil {
		if !missing(err) {
			return a, f, rt, g, nil, time.Time{}, err
		}
		return a, f, rt, g, nil, time.Time{}, d.ErrToken
	}
	if a.AccountRevision <= 0 || a.AccountRevision != f.AccountRevision || a.AuthID != f.AuthID || a.GrantID != f.GrantID || a.GrantEpoch != f.GrantEpoch || a.ClientEpoch != f.ClientEpoch || a.Runtime.Client.ID != f.ClientID || a.Runtime.Client.ApplicationID != f.ApplicationID || a.Runtime.Client.Channel != f.Channel || a.Runtime.Major != f.Major || a.Runtime.TesterID != f.TesterID {
		return a, f, rt, g, nil, time.Time{}, d.ErrToken
	}
	rt, g, c, err := s.currentSnapshot(ctx, tx, f)
	if err != nil {
		if !errors.Is(err, d.ErrUnavailable) {
			err = d.ErrToken
		}
		return a, f, rt, g, nil, time.Time{}, err
	}
	observedAt := s.now()
	if !a.ExpiresAt.After(observedAt) || f.Revoked || !f.IdleExpiresAt.After(observedAt) || !f.AbsoluteExpiresAt.After(observedAt) {
		return a, f, rt, g, nil, observedAt, d.ErrToken
	}
	if !rt.Fresh(observedAt) {
		return a, f, rt, g, nil, observedAt, d.ErrUnavailable
	}
	effective := d.Intersect(a.Scopes, g.Scopes, d.Union(rt.Required, rt.Optional), c.Enabled(s.cfg.RefreshEnabled))
	return a, f, rt, g, effective, observedAt, nil
}
func (s *Service) UserInfo(ctx context.Context, raw string) (d.UserInfo, error) {
	var out d.UserInfo
	err := s.transaction(ctx, func(tx port.Tx) error {
		out = d.UserInfo{}
		a, f, _, _, scopes, observedAt, err := s.access(ctx, tx, raw)
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
		if d.Contains(scopes, "campus.whut") {
			certification, err := tx.CampusCertification(f.AuthID)
			if err != nil && !missing(err) {
				return d.ErrUnavailable
			}
			if err == nil {
				if certification.AuthID != f.AuthID || certification.Institution != "WHUT" || certification.CertifiedAt.UnixMilli() <= 0 || certification.CertifiedAt.After(observedAt) {
					return d.ErrUnavailable
				}
				out.Campus = &certification
			}
		}
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
				if value.Type == "ACADEMIC_GRADE" {
					if value.Academic == nil || value.Academic.ConfirmedAt == nil || value.Academic.ConfirmedAt.IsZero() || value.Academic.Year <= 0 || value.Academic.FinalYear <= 0 || value.Academic.Year > value.Academic.FinalYear || value.Academic.AcademicYear <= 0 || value.Academic.Stage != "UNDERGRADUATE" && value.Academic.Stage != "MASTER" && value.Academic.Stage != "DOCTORAL" {
						return d.ErrUnavailable
					}
					current, calendarErr := tx.AcademicYear(observedAt)
					if calendarErr != nil || current < value.Academic.AcademicYear {
						return d.ErrUnavailable
					}
					effective := int64(value.Academic.Year) + int64(current) - int64(value.Academic.AcademicYear)
					if effective > int64(value.Academic.FinalYear) {
						effective = int64(value.Academic.FinalYear)
					}
					if effective <= 0 || effective > int64(^uint32(0)>>1) {
						return d.ErrUnavailable
					}
					value.Integer = int32(effective)
				}
				out.Profile = append(out.Profile, d.ProfileEntry{Key: definition.ProfileField, Value: value})
			}
		}
		return nil
	})
	if err != nil {
		return d.UserInfo{}, err
	}
	return out, nil
}
