package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"iwut-auth-center/internal/adapter/transport"
	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/usecase"
)

// Route field order is part of the v1 canonical digest contract. Callers are
// local authorization and are excluded from the shared route-policy digest.
type oauthRouteJSON struct {
	ID       string   `json:"routeId"`
	Audience string   `json:"audience"`
	Protocol string   `json:"protocol"`
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	Scopes   []string `json:"requiredScopes"`
	Channels []string `json:"allowedChannels"`
}
type routePolicy struct {
	Version int                                        `json:"version"`
	Routes  []oauthRouteJSON                           `json:"routes"`
	Callers map[string]transport.OAuthDelegationCaller `json:"callers"`
}

func loadOAuthRoutes(path string, uc *usecase.Service) (*transport.OAuthDelegationService, error) {
	out := &transport.OAuthDelegationService{Service: uc, Routes: map[string]d.Route{}, Callers: map[string]transport.OAuthDelegationCaller{}}
	if path == "" {
		return out, nil
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 128*1024))
	dec.DisallowUnknownFields()
	var policy routePolicy
	if dec.Decode(&policy) != nil || dec.Decode(&struct{}{}) != io.EOF || policy.Version != 1 {
		return nil, fmt.Errorf("invalid OAuth route policy")
	}
	sort.Slice(policy.Routes, func(i, j int) bool { return policy.Routes[i].ID < policy.Routes[j].ID })
	for i, r := range policy.Routes {
		if r.ID == "" || r.Audience == "" || len(r.Scopes) == 0 || !d.ValidScopes(r.Scopes) || !validOAuthChannels(r.Channels) || r.Protocol != "HTTP" && r.Protocol != "GRPC" || r.Method == "" || r.Protocol == "HTTP" && !validOAuthPathPattern(r.Path) || r.Protocol == "GRPC" && (r.Path != "" || !validOAuthGRPCMethod(r.Method)) {
			return nil, fmt.Errorf("invalid OAuth route")
		}
		if r.Protocol == "HTTP" && !d.Contains([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}, r.Method) {
			return nil, fmt.Errorf("invalid OAuth HTTP method")
		}
		if _, ok := out.Routes[r.ID]; ok {
			return nil, fmt.Errorf("duplicate OAuth route")
		}
		for _, old := range out.Routes {
			if old.Protocol == r.Protocol && old.Method == r.Method && (r.Protocol == "GRPC" || oauthPathsOverlap(old.Path, r.Path)) {
				return nil, fmt.Errorf("ambiguous OAuth routes")
			}
		}
		out.Routes[r.ID] = d.Route{ID: r.ID, Audience: r.Audience, Protocol: r.Protocol, Method: r.Method, Path: r.Path, Scopes: r.Scopes, Channels: r.Channels}
		policy.Routes[i].Scopes = d.Union(r.Scopes)
		policy.Routes[i].Channels = d.Union(r.Channels)
	}
	raw, _ := json.Marshal(struct {
		Version int              `json:"version"`
		Routes  []oauthRouteJSON `json:"routes"`
	}{policy.Version, policy.Routes})
	hash := sha256.Sum256(raw)
	out.Digest = hex.EncodeToString(hash[:])
	out.Callers = policy.Callers
	for id, c := range policy.Callers {
		if id == "" || len(c.Routes) == 0 || len(c.Audiences) == 0 {
			return nil, fmt.Errorf("invalid OAuth caller")
		}
		for _, route := range c.Routes {
			r, ok := out.Routes[route]
			if !ok || !d.Contains(c.Audiences, r.Audience) {
				return nil, fmt.Errorf("invalid caller route")
			}
		}
	}
	return out, nil
}
func validOAuthGRPCMethod(v string) bool {
	parts := strings.Split(v, "/")
	return len(parts) == 3 && parts[0] == "" && strings.Contains(parts[1], ".") && parts[2] != "" && !strings.ContainsAny(v, " {}?%\\\n\r")
}
func validOAuthPathPattern(v string) bool {
	if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "?#%\\\x00\r\n ") || strings.Contains(v, "//") {
		return false
	}
	for _, seg := range strings.Split(v, "/")[1:] {
		if seg == "." || seg == ".." || seg == "" {
			return false
		}
		if strings.ContainsAny(seg, "{}") {
			if len(seg) < 3 || seg[0] != '{' || seg[len(seg)-1] != '}' || strings.ContainsAny(seg[1:len(seg)-1], "{}") {
				return false
			}
		}
	}
	return true
}
func oauthPathsOverlap(a, b string) bool {
	x, y := strings.Split(a, "/"), strings.Split(b, "/")
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if v != y[i] && !strings.HasPrefix(v, "{") && !strings.HasPrefix(y[i], "{") {
			return false
		}
	}
	return true
}

func validOAuthChannels(channels []string) bool {
	if len(channels) == 0 || len(d.Union(channels)) != len(channels) {
		return false
	}
	for _, channel := range channels {
		if !d.ValidChannel(channel) {
			return false
		}
	}
	return true
}
