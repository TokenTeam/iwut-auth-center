package transport

import (
	"context"
	"encoding/base64"
	d "iwut-auth-center/internal/oauth/domain"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type OAuthPublicContext struct {
	ClientID string
	Major    int32
}

func oauthProof(r *http.Request, v url.Values) (d.ClientProof, error) {
	headers := r.Header.Values("Authorization")
	if len(headers) == 0 {
		if v.Get("client_id") == "" {
			return d.ClientProof{}, d.ErrClient
		}
		return d.ClientProof{ClientID: v.Get("client_id")}, nil
	}
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Basic ") || v.Has("client_id") {
		return d.ClientProof{}, d.ErrClient
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(headers[0], "Basic "))
	if e != nil {
		return d.ClientProof{}, d.ErrClient
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return d.ClientProof{}, d.ErrClient
	}
	id, e := url.QueryUnescape(parts[0])
	if e != nil {
		return d.ClientProof{}, d.ErrClient
	}
	secret, e := url.QueryUnescape(parts[1])
	if e != nil || id == "" || secret == "" {
		return d.ClientProof{}, d.ErrClient
	}
	return d.ClientProof{ClientID: id, Secret: secret, Basic: true}, nil
}
func oauthBearer(r *http.Request) (string, error) {
	v := r.Header.Values("Authorization")
	if len(v) != 1 || !strings.HasPrefix(v[0], "Bearer ") || !canonicalSessionToken(strings.TrimPrefix(v[0], "Bearer ")) {
		return "", d.ErrToken
	}
	return strings.TrimPrefix(v[0], "Bearer "), nil
}
func (h *OAuthHTTP) cors(w http.ResponseWriter, r *http.Request, client string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if len(r.Header.Values("Origin")) != 1 || origin == "null" {
		oauthError(w, d.ErrClient)
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	allowed, err := h.Service.AllowOrigin(ctx, client, origin)
	if err != nil {
		oauthError(w, err)
		return false
	}
	if allowed {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
		return true
	}
	for _, c := range h.PublicContexts {
		if client != "" && c.ClientID != client {
			continue
		}
		allowed, e := h.Service.PublicOrigin(ctx, c.ClientID, c.Major, origin)
		if e != nil {
			if e == d.ErrUnavailable {
				oauthError(w, e)
				return false
			}
			continue
		}
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			return true
		}
	}
	oauthError(w, d.ErrClient)
	return false
}
func (h *OAuthHTTP) preflight(w http.ResponseWriter, r *http.Request, path string) {
	if r.URL.RawQuery != "" || path != "/token" && path != "/revoke" && path != "/userinfo" {
		oauthError(w, d.ErrRequest)
		return
	}
	method := r.Header.Get("Access-Control-Request-Method")
	if method != "POST" && !(path == "/userinfo" && method == "GET") {
		oauthError(w, d.ErrRequest)
		return
	}
	for _, header := range strings.Split(strings.ToLower(r.Header.Get("Access-Control-Request-Headers")), ",") {
		switch strings.TrimSpace(header) {
		case "", "authorization", "content-type":
		default:
			oauthError(w, d.ErrRequest)
			return
		}
	}
	if !h.cors(w, r, "") {
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type")
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
	w.WriteHeader(204)
}
func (h *OAuthHTTP) token(w http.ResponseWriter, r *http.Request) {
	v, e := oauthForm(r, "grant_type code redirect_uri code_verifier refresh_token scope client_id")
	if e != nil || r.Method != "POST" {
		oauthError(w, d.ErrRequest)
		return
	}
	proof, e := oauthProof(r, v)
	if e != nil {
		oauthError(w, e)
		return
	}
	if !h.cors(w, r, proof.ClientID) {
		return
	}
	if !h.rate("client:"+proof.ClientID, oauthLimit(h.ClientPerMinute, 300)) {
		w.Header().Set("Retry-After", "60")
		oauthJSON(w, 429, map[string]string{"error": "slow_down"})
		return
	}
	var out d.TokenResponse
	switch v.Get("grant_type") {
	case "authorization_code":
		if v.Has("refresh_token") || v.Has("scope") {
			oauthError(w, d.ErrRequest)
			return
		}
		out, e = h.Service.Exchange(r.Context(), proof, v.Get("code"), v.Get("redirect_uri"), v.Get("code_verifier"))
	case "refresh_token":
		if v.Has("code") || v.Has("redirect_uri") || v.Has("code_verifier") {
			oauthError(w, d.ErrRequest)
			return
		}
		var scopes []string
		if v.Has("scope") {
			scopes, e = d.ParseScopes(v.Get("scope"))
			if e != nil {
				oauthError(w, e)
				return
			}
		}
		out, e = h.Service.Refresh(r.Context(), proof, v.Get("refresh_token"), scopes)
	default:
		oauthJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	if e != nil {
		oauthError(w, e)
		return
	}
	response := map[string]any{"access_token": out.AccessToken, "token_type": "Bearer", "expires_in": out.ExpiresIn, "scope": strings.Join(out.Scopes, " ")}
	if out.RefreshToken != "" {
		response["refresh_token"] = out.RefreshToken
	}
	if out.IDToken != "" {
		response["id_token"] = out.IDToken
	}
	oauthJSON(w, 200, response)
}
func (h *OAuthHTTP) revoke(w http.ResponseWriter, r *http.Request) {
	v, e := oauthForm(r, "token token_type_hint client_id")
	if e != nil || r.Method != "POST" || v.Get("token") == "" {
		oauthError(w, d.ErrRequest)
		return
	}
	proof, e := oauthProof(r, v)
	if e != nil {
		oauthError(w, e)
		return
	}
	if !h.cors(w, r, proof.ClientID) {
		return
	}
	if !h.rate("client:"+proof.ClientID, oauthLimit(h.ClientPerMinute, 300)) {
		w.Header().Set("Retry-After", "60")
		oauthJSON(w, 429, map[string]string{"error": "slow_down"})
		return
	}
	hint := v.Get("token_type_hint")
	if hint != "" && hint != "access_token" && hint != "refresh_token" {
		oauthJSON(w, 400, map[string]string{"error": "unsupported_token_type"})
		return
	}
	e = h.Service.RevokeToken(r.Context(), proof, v.Get("token"), hint)
	if e != nil {
		oauthError(w, e)
		return
	}
	w.WriteHeader(200)
}
func (h *OAuthHTTP) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" || r.URL.RawQuery != "" {
		oauthError(w, d.ErrRequest)
		return
	}
	v, e := oauthForm(r, "")
	if e != nil || len(v) != 0 {
		oauthError(w, d.ErrRequest)
		return
	}
	raw, e := oauthBearer(r)
	if e != nil {
		oauthError(w, e)
		return
	}
	if r.Header.Get("Origin") != "" {
		id, e := h.Service.AccessClient(r.Context(), raw)
		if e != nil {
			oauthError(w, d.ErrToken)
			return
		}
		if !h.cors(w, r, id) {
			return
		}
	}
	out, e := h.Service.UserInfo(r.Context(), raw)
	if e != nil {
		oauthError(w, e)
		return
	}
	response, e := userInfoResponse(out)
	if e != nil {
		oauthError(w, e)
		return
	}
	oauthJSON(w, 200, response)
}

func userInfoResponse(out d.UserInfo) (map[string]any, error) {
	response := map[string]any{"sub": out.Subject}
	if out.EmailVerified {
		response["email"] = out.Email
		response["email_verified"] = true
	}
	if out.Campus != nil {
		if out.Campus.Institution != "WHUT" || out.Campus.CertifiedAt.UnixMilli() <= 0 {
			return nil, d.ErrUnavailable
		}
		response["iwut_campus"] = map[string]any{"institution": "WHUT", "certified": true}
	}
	if len(out.Profile) > 0 {
		profile := map[string]any{}
		for _, entry := range out.Profile {
			switch entry.Value.Type {
			case "STRING", "DATE":
				profile[entry.Key] = entry.Value.Text
			case "INTEGER":
				profile[entry.Key] = entry.Value.Integer
			case "BOOLEAN":
				profile[entry.Key] = entry.Value.Boolean
			case "STRING_SET":
				profile[entry.Key] = append([]string(nil), entry.Value.Strings...)
			case "ACADEMIC_GRADE":
				if entry.Value.Academic == nil {
					return nil, d.ErrUnavailable
				}
				profile[entry.Key] = entry.Value.Academic.Stage + "_" + strconv.FormatInt(int64(entry.Value.Integer), 10)
			default:
				return nil, d.ErrUnavailable
			}
		}
		response["iwut_profile"] = profile
	}
	return response, nil
}
