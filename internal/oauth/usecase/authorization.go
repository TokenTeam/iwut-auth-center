package usecase

import (
	"context"
	"crypto/subtle"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
	"net/url"
	"time"
)

func (s *Service) Begin(ctx context.Context, q d.AuthorizationRequest, session string) (d.AuthorizationView, error) {
	var out d.AuthorizationView
	client, err := s.app.Client(ctx, q.ClientID)
	if err != nil {
		return out, err
	}
	if !d.ValidChannel(q.Channel) || client.Channel != q.Channel || q.Major < 1 {
		return out, d.ErrRequest
	}
	rt, err := s.app.Runtime(ctx, client, q.Major)
	if err != nil {
		return out, err
	}
	// Callback trust is established before an interaction or redirect can exist.
	if !d.Contains(rt.Redirects, q.RedirectURI) {
		return out, d.ErrRequest
	}
	if len(q.State) < 43 || len(q.State) > 128 || !base64Text(q.State) || len(q.Nonce) < 43 || len(q.Nonce) > 128 || !base64Text(q.Nonce) {
		return out, d.ErrRequest
	}
	if q.Prompt != "" && q.Prompt != "none" && q.Prompt != "login" && q.Prompt != "consent" || q.MaxAge != nil && *q.MaxAge < 0 {
		return out, d.ErrRequest
	}
	if client.Type == "PUBLIC_PKCE" && q.Challenge == "" || q.Challenge != "" && (q.ChallengeMethod != "S256" || !s.crypto.ValidChallenge(q.Challenge)) || q.Challenge == "" && q.ChallengeMethod != "" {
		return out, d.ErrRequest
	}
	if d.Contains(q.Scopes, "offline_access") && q.Prompt != "consent" {
		return out, d.ErrRequest
	}
	id, err := s.crypto.Random()
	if err != nil {
		return out, d.ErrUnavailable
	}
	csrf, err := s.crypto.Random()
	if err != nil {
		return out, d.ErrUnavailable
	}
	err = s.transaction(ctx, func(tx port.Tx) error {
		out = d.AuthorizationView{}
		if err := applicationOpen(tx, rt.Client.ApplicationID); err != nil {
			return err
		}
		if _, err := s.checkScopes(tx, rt, q.Scopes); err != nil {
			return err
		}
		if err := s.ensureSector(ctx, tx, rt); err != nil {
			return err
		}
		i := d.Interaction{ID: id, CSRFHash: s.crypto.Digest("csrf", csrf), Status: "PENDING", Request: q, Runtime: rt, ExpiresAt: s.now().Add(10 * time.Minute)}
		if session != "" {
			ss, e := tx.Session(session, s.now())
			if e == nil {
				i.InitialSessionID = ss.ID
			} else if e != d.ErrLogin {
				return e
			}
		}
		if err := tx.SaveInteraction(i); err != nil {
			return err
		}
		return s.fresh(rt)
	})
	if err != nil {
		return out, err
	}
	return s.View(ctx, id, csrf, session)
}
func base64Text(s string) bool {
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return s != ""
}
func (s *Service) View(ctx context.Context, id, csrf, session string) (d.AuthorizationView, error) {
	var out d.AuthorizationView
	err := s.transaction(ctx, func(tx port.Tx) error {
		out = d.AuthorizationView{}
		i, err := tx.Interaction(id)
		if err != nil {
			return err
		}
		if err := applicationOpen(tx, i.Runtime.Client.ApplicationID); err != nil {
			return err
		}
		if i.Status != "PENDING" || !i.ExpiresAt.After(s.now()) {
			return d.ErrRequest
		}
		// Only the browser that established this interaction can render its consent.
		if subtle.ConstantTimeCompare([]byte(i.CSRFHash), []byte(s.crypto.Digest("csrf", csrf))) != 1 {
			return d.ErrRequest
		}
		out = d.AuthorizationView{InteractionID: id, CSRF: csrf, Channel: i.Runtime.Client.Channel}
		ss, e := tx.Session(session, s.now())
		if e != nil && e != d.ErrLogin {
			return e
		}
		if e != nil || i.Request.Prompt == "login" && ss.ID == i.InitialSessionID || i.Request.MaxAge != nil && s.now().Unix()-ss.AuthenticatedAt.Unix() > *i.Request.MaxAge {
			if i.Request.Prompt == "none" {
				out.Redirect = callback(i.Request, "", "login_required", s.cfg.Issuer)
				i.Status = "DENIED"
				return tx.SaveInteraction(i)
			}
			out.LoginRequired = true
			return nil
		}
		if i.AuthID != "" && (i.AccountRevision != ss.AccountRevision || i.AuthID != ss.AuthID || i.SessionID != ss.ID) {
			return d.ErrConflict
		}
		rt, err := s.app.Authorize(ctx, i.Runtime, ss.AuthID)
		if err != nil {
			return err
		}
		if i.AuthID != "" && !i.Runtime.SameTuple(rt) {
			return d.ErrConflict
		}
		if _, err := s.user(tx, ss.AuthID, rt); err != nil {
			return err
		}
		catalog, err := s.checkScopes(tx, rt, i.Request.Scopes)
		if err != nil {
			return err
		}
		g, err := tx.FindGrant(ss.AuthID, rt.Client.ApplicationID, rt.Client.Channel)
		if err != nil && !missing(err) {
			return err
		}
		i.AccountRevision = ss.AccountRevision
		i.AuthID = ss.AuthID
		i.SessionID = ss.ID
		i.AuthenticatedAt = ss.AuthenticatedAt
		i.Runtime = rt
		i.GrantRevision = g.Revision
		out.DisplayName = rt.DisplayName
		owner, err := tx.User(rt.AdminID)
		if err != nil {
			return err
		}
		out.DeveloperHandle = owner.DeveloperHandle
		out.Requested = i.Request.Scopes
		out.Required = rt.Required
		out.Definitions = catalog.Scopes
		if g.Status == "ACTIVE" {
			out.PreviouslyGranted = g.Scopes
		}
		if err := tx.SaveInteraction(i); err != nil {
			return err
		}
		if i.Request.Prompt != "consent" && i.Request.Prompt != "login" && g.Status == "ACTIVE" && d.Subset(i.Request.Scopes, g.Scopes) {
			out.Redirect, err = s.confirm(ctx, tx, i, ss, i.Request.Scopes, true)
			return err
		}
		if i.Request.Prompt == "none" {
			out.Redirect = callback(i.Request, "", "consent_required", s.cfg.Issuer)
			i.Status = "DENIED"
			return tx.SaveInteraction(i)
		}
		return s.fresh(rt)
	})
	if err != nil {
		return d.AuthorizationView{}, err
	}
	return out, nil
}
func (s *Service) Confirm(ctx context.Context, id, csrf, session string, selected []string, approve bool) (string, error) {
	var redirect string
	err := s.transaction(ctx, func(tx port.Tx) error {
		redirect = ""
		i, err := tx.Interaction(id)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(i.CSRFHash), []byte(s.crypto.Digest("csrf", csrf))) != 1 {
			return d.ErrRequest
		}
		ss, err := tx.Session(session, s.now())
		if err != nil {
			return err
		}
		redirect, err = s.confirm(ctx, tx, i, ss, selected, approve)
		return err
	})
	if err != nil {
		return "", err
	}
	return redirect, nil
}
func (s *Service) confirm(ctx context.Context, tx port.Tx, i d.Interaction, ss d.Session, selected []string, approve bool) (string, error) {
	if err := applicationOpen(tx, i.Runtime.Client.ApplicationID); err != nil {
		return "", err
	}
	if i.Status != "PENDING" || !i.ExpiresAt.After(s.now()) || i.AccountRevision != ss.AccountRevision || i.AuthID != ss.AuthID || i.SessionID != ss.ID {
		return "", d.ErrConflict
	}
	if !approve {
		i.Status = "DENIED"
		if err := tx.SaveInteraction(i); err != nil {
			return "", err
		}
		return callback(i.Request, "", "access_denied", s.cfg.Issuer), nil
	}
	rt, err := s.app.Authorize(ctx, i.Runtime, ss.AuthID)
	if err != nil {
		return "", err
	}
	if !i.Runtime.SameTuple(rt) {
		return "", d.ErrConflict
	}
	if _, err := s.user(tx, ss.AuthID, rt); err != nil {
		return "", err
	}
	if _, err := s.checkScopes(tx, rt, i.Request.Scopes); err != nil {
		return "", err
	}
	if !d.ValidScopes(selected) || !d.Contains(selected, "openid") || !d.Subset(rt.Required, selected) || !d.Subset(selected, i.Request.Scopes) {
		return "", d.ErrScope
	}
	g, err := tx.FindGrant(ss.AuthID, rt.Client.ApplicationID, rt.Client.Channel)
	if err != nil && !missing(err) {
		return "", err
	}
	if g.Revision != i.GrantRevision {
		return "", d.ErrConflict
	}
	now := s.now()
	if g.ID == "" {
		g = d.Grant{ID: s.crypto.ID(), AuthID: ss.AuthID, ApplicationID: rt.Client.ApplicationID, Channel: rt.Client.Channel, RevocationEpoch: 1, CreatedAt: now}
	}
	if g.Status != "ACTIVE" || !d.Subset(selected, g.Scopes) {
		g.Scopes = d.Union(g.Scopes, selected)
		g.Revision++
		g.Status = "ACTIVE"
		g.UpdatedAt = now
	}
	g.DisplayName = rt.DisplayName
	raw, err := s.crypto.Random()
	if err != nil {
		return "", d.ErrUnavailable
	}
	code := d.Code{AccountRevision: ss.AccountRevision, Digest: s.crypto.Digest("code", raw), AuthID: ss.AuthID, ClientID: rt.Client.ID, GrantID: g.ID, RedirectURI: i.Request.RedirectURI, Nonce: i.Request.Nonce, Challenge: i.Request.Challenge, Scopes: d.Union(selected), Runtime: rt, GrantRevision: g.Revision, GrantEpoch: g.RevocationEpoch, AuthenticatedAt: ss.AuthenticatedAt, ExpiresAt: now.Add(90 * time.Second)}
	if err := tx.SaveGrant(g); err != nil {
		return "", err
	}
	if err := tx.SaveCode(code); err != nil {
		return "", err
	}
	i.Status = "APPROVED"
	if err := tx.SaveInteraction(i); err != nil {
		return "", err
	}
	if err := s.audit(tx, g, rt.Client.ID, "AUTHORIZE", selected); err != nil {
		return "", err
	}
	if err := s.fresh(rt); err != nil {
		return "", err
	}
	return callback(i.Request, raw, "", s.cfg.Issuer), nil
}
func callback(q d.AuthorizationRequest, code, reason, issuer string) string {
	u, _ := url.Parse(q.RedirectURI)
	v := u.Query()
	v.Set("state", q.State)
	v.Set("iss", issuer)
	if reason != "" {
		v.Set("error", reason)
	} else {
		v.Set("code", code)
	}
	u.RawQuery = v.Encode()
	return u.String()
}
func (s *Service) PortalSession(ctx context.Context, token string) (d.Session, error) {
	var out d.Session
	err := s.transaction(ctx, func(tx port.Tx) error { var err error; out, err = tx.Session(token, s.now()); return err })
	if err != nil {
		return d.Session{}, err
	}
	return out, nil
}
