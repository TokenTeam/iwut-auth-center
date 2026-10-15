package usecase

import (
	"context"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/port"
	"net/url"
	"strings"
	"time"
)

func (s *Service) Delegate(ctx context.Context, raw string, q d.DelegationRequest, route d.Route, digest string) (d.Delegation, error) {
	var out d.Delegation
	if s.cfg.SigningHealthy == nil || !s.cfg.SigningHealthy() {
		return out, d.ErrUnavailable
	}
	if q.PolicyDigest != digest || digest == "" {
		return out, d.ErrUnavailable
	}
	if q.RouteID != route.ID || q.Protocol != route.Protocol || q.Method != route.Method || len(route.Scopes) == 0 || route.Audience == "" {
		return out, d.ErrRequest
	}
	if q.Protocol == "HTTP" {
		if !matchPath(route.Path, q.TargetPath) {
			return out, d.ErrRequest
		}
	} else if q.Protocol != "GRPC" || q.TargetPath != "" {
		return out, d.ErrRequest
	}
	err := s.transaction(ctx, func(tx port.Tx) error {
		out = d.Delegation{}
		a, f, _, g, scopes, now, err := s.access(ctx, tx, raw)
		if err != nil {
			return err
		}
		if !d.Contains(a.Audiences, route.Audience) || !d.Contains(route.Channels, f.Channel) || !d.Subset(route.Scopes, scopes) {
			return d.ErrInsufficient
		}
		catalog, err := s.catalog(tx)
		if err != nil {
			return err
		}
		for _, required := range route.Scopes {
			mapped := false
			for _, v := range catalog.Scopes {
				if v.Name == required && v.Enabled && v.Kind == "RESOURCE" && v.Audience == route.Audience {
					mapped = true
				}
			}
			if !mapped {
				return d.ErrInsufficient
			}
		}
		exp := earliest(now.Add(5*time.Second), a.ExpiresAt)
		if exp.Unix() <= now.Unix() {
			return d.ErrToken
		}
		claims := map[string]any{"iss": s.cfg.Issuer, "aud": route.Audience, "sub": f.AuthID, "client_id": f.ClientID, "application_id": f.ApplicationID, "grant_id": g.ID, "grant_revision": g.Revision, "grant_revocation_epoch": g.RevocationEpoch, "channel": f.Channel, "rpc_api_major": f.Major, "client_authorization_epoch": f.ClientEpoch, "scopes": scopes, "route_id": route.ID, "policy_digest": digest, "protocol": q.Protocol, "method": q.Method, "iat": now.Unix(), "nbf": now.Unix(), "exp": exp.Unix(), "jti": s.crypto.ID()}
		if q.Protocol == "HTTP" {
			claims["target_path"] = q.TargetPath
		}
		token, err := s.crypto.SignDelegation(claims)
		if err != nil {
			return err
		}
		out = d.Delegation{Token: token, ExpiresAt: time.Unix(exp.Unix(), 0).UTC()}
		if !s.cfg.SigningHealthy() {
			return d.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return d.Delegation{}, err
	}
	return out, nil
}

// Paths use literal segments or an entire {parameter} segment. A single
// canonical unescape is required; encoded separators and dot paths fail closed.
func matchPath(pattern, path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\\") || strings.Contains(path, "//") {
		return false
	}
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return false
	}
	lower := strings.ToLower(path)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(decoded, "%") || strings.ContainsAny(decoded, "\\\x00\r\n") {
		return false
	}
	a, b := strings.Split(pattern, "/"), strings.Split(decoded, "/")
	if len(a) != len(b) {
		return false
	}
	for i, v := range b {
		if v == "." || v == ".." {
			return false
		}
		if a[i] == v {
			continue
		}
		if v == "" || !strings.HasPrefix(a[i], "{") || !strings.HasSuffix(a[i], "}") {
			return false
		}
	}
	return true
}
