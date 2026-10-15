package transport

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	d "iwut-auth-center/internal/oauth/domain"
	"iwut-auth-center/internal/oauth/usecase"
)

// OAuthHTTP owns standard protocol serialization; it never uses the Proto JSON
// envelope or accepts forwarded identity headers as a platform Session.
type OAuthHTTP struct {
	IPPerMinute, ClientPerMinute, UserConfirmPerMinute int
	PublicContexts                                     []OAuthPublicContext
	Service                                            *usecase.Service
	Issuer, Origin, LoginURL, SectorSuffix             string
	Enabled                                            bool
	StorageEnabled                                     bool
	mu                                                 sync.Mutex
	buckets                                            map[string]oauthBucket
}
type oauthBucket struct {
	minute int64
	count  int
}

func (h *OAuthHTTP) Handles(r *http.Request) bool {
	if r.URL.Path == "/v1/application-user-storage:batchGet" || r.URL.Path == "/v1/application-user-storage:mutate" {
		return true
	}
	u, _ := url.Parse(h.Issuer)
	if r.URL.Path == "/redirect-uris.json" && strings.HasSuffix(r.Host, "."+h.SectorSuffix) {
		return true
	}
	if u.Path != "" {
		return r.URL.Path == u.Path || strings.HasPrefix(r.URL.Path, u.Path+"/")
	}
	if strings.HasPrefix(r.URL.Path, "/portal/interactions/") && strings.HasSuffix(r.URL.Path, "/confirm") {
		return true
	}
	switch r.URL.Path {
	case "/authorize", "/token", "/revoke", "/userinfo", "/jwks", "/.well-known/openid-configuration", "/portal/session", "/portal/interaction", "/portal/confirm":
		return true
	}
	return false
}

// ObservableOperation returns a bounded operation name for every request that
// Handles accepts. It deliberately never returns the request path, host,
// interaction id, client id or any other caller-controlled value.
func (h *OAuthHTTP) ObservableOperation(r *http.Request) string {
	switch r.URL.Path {
	case "/v1/application-user-storage:batchGet":
		return "application_user_storage.batch_get"
	case "/v1/application-user-storage:mutate":
		return "application_user_storage.mutate"
	}
	if r.URL.Path == "/redirect-uris.json" && strings.HasSuffix(r.Host, "."+h.SectorSuffix) {
		return "oauth.redirect_uris"
	}
	u, _ := url.Parse(h.Issuer)
	path := strings.TrimPrefix(r.URL.Path, u.Path)
	switch path {
	case "/authorize":
		return "oauth.authorize"
	case "/token":
		return "oauth.token"
	case "/revoke":
		return "oauth.revoke"
	case "/userinfo":
		return "oauth.userinfo"
	case "/jwks":
		return "oauth.jwks"
	case "/.well-known/openid-configuration":
		return "oauth.discovery"
	case "/portal/session":
		return "oauth.portal.session"
	case "/portal/interaction":
		return "oauth.portal.interaction"
	}
	if strings.HasPrefix(path, "/portal/interactions/") && strings.HasSuffix(path, "/confirm") {
		return "oauth.portal.confirm"
	}
	return "oauth.unmatched"
}

func (h *OAuthHTTP) rate(key string, limit int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now().Unix() / 60
	if h.buckets == nil {
		h.buckets = map[string]oauthBucket{}
	}
	if len(h.buckets) > 10000 {
		for k, v := range h.buckets {
			if v.minute != now {
				delete(h.buckets, k)
			}
		}
		if len(h.buckets) > 10000 {
			return false
		}
	}
	v := h.buckets[key]
	if v.minute != now {
		v = oauthBucket{minute: now}
	}
	v.count++
	h.buckets[key] = v
	return v.count <= limit
}
func (h *OAuthHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.URL.Path == "/v1/application-user-storage:batchGet" || r.URL.Path == "/v1/application-user-storage:mutate" {
		if !h.StorageEnabled {
			http.NotFound(w, r)
			return
		}
		h.applicationUserStorage(w, r)
		return
	}
	if !h.Enabled {
		http.NotFound(w, r)
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !h.rate("ip:"+host, oauthLimit(h.IPPerMinute, 120)) {
		w.Header().Set("Retry-After", "60")
		w.Header().Set("Retry-After", "60")
		oauthJSON(w, 429, map[string]string{"error": "slow_down"})
		return
	}
	if r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		oauthError(w, d.ErrRequest)
		return
	}
	u, _ := url.Parse(h.Issuer)
	path := strings.TrimPrefix(r.URL.Path, u.Path)
	if r.URL.Path == "/redirect-uris.json" {
		if r.Method != "GET" || r.URL.RawQuery != "" {
			oauthError(w, d.ErrRequest)
			return
		}
		v, e := h.Service.SectorRedirects(r.Context(), r.Host)
		if e != nil {
			if errors.Is(e, d.ErrNotFound) {
				http.NotFound(w, r)
			} else {
				oauthError(w, e)
			}
			return
		}
		oauthJSON(w, 200, v)
		return
	}
	if r.Method == "OPTIONS" {
		h.preflight(w, r, path)
		return
	}
	switch path {
	case "/token":
		h.token(w, r)
	case "/revoke":
		h.revoke(w, r)
	case "/userinfo":
		h.userinfo(w, r)
	case "/jwks":
		if r.Method != "GET" || r.URL.RawQuery != "" {
			oauthError(w, d.ErrRequest)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		oauthJSON(w, 200, h.Service.JWKS())
	case "/.well-known/openid-configuration":
		if r.Method != "GET" || r.URL.RawQuery != "" {
			oauthError(w, d.ErrRequest)
			return
		}
		v, e := h.Service.Discovery(r.Context())
		if e != nil {
			oauthError(w, e)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=60")
		oauthJSON(w, 200, v)
	case "/authorize":
		h.authorize(w, r)
	case "/portal/session":
		h.portalSession(w, r)
	case "/portal/interaction":
		h.view(w, r)

	default:
		if strings.HasPrefix(path, "/portal/interactions/") && strings.HasSuffix(path, "/confirm") {
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/portal/interactions/"), "/confirm")
			if canonicalSessionToken(id) {
				h.confirm(w, r, id)
				return
			}
		}
		http.NotFound(w, r)
	}
}
func oauthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func oauthError(w http.ResponseWriter, err error) {
	code := 400
	name := err.Error()
	switch {
	case errors.Is(err, d.ErrUnavailable):
		code = 503
		name = "temporarily_unavailable"
	case errors.Is(err, d.ErrClient):
		code = 401
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
	case errors.Is(err, d.ErrToken):
		code = 401
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	case errors.Is(err, d.ErrInsufficient):
		code = 403
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
	case errors.Is(err, d.ErrConflict):
		code = 409
	case errors.Is(err, d.ErrNotFound):
		code = 404
	case errors.Is(err, d.ErrLogin):
		code = 401
	default:
		if !errors.Is(err, d.ErrRequest) && !errors.Is(err, d.ErrGrant) && !errors.Is(err, d.ErrScope) && !errors.Is(err, d.ErrConsent) {
			name = "temporarily_unavailable"
			code = 503
		}
	}
	oauthJSON(w, code, map[string]string{"error": name})
}
func oauthForm(r *http.Request, allowed string) (url.Values, error) {
	var raw string
	if r.Method == "GET" {
		b, e := io.ReadAll(io.LimitReader(r.Body, 1))
		if e != nil || len(b) != 0 || len(r.URL.RawQuery) > 16*1024 {
			return nil, d.ErrRequest
		}
		raw = r.URL.RawQuery
	} else if r.Method == "POST" {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
			return nil, d.ErrRequest
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
		if e != nil || len(b) > 16*1024 {
			return nil, d.ErrRequest
		}
		raw = string(b)
	} else {
		return nil, d.ErrRequest
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return nil, d.ErrRequest
	}
	for key, values := range v {
		if len(values) != 1 || !strings.Contains(" "+allowed+" ", " "+key+" ") {
			return nil, d.ErrRequest
		}
	}
	return v, nil
}
func portalToken(r *http.Request) string {
	cookies := r.CookiesNamed("__Host-iwut-portal")
	if len(cookies) != 1 {
		return ""
	}
	return cookies[0].Value
}
func (h *OAuthHTTP) authorize(w http.ResponseWriter, r *http.Request) {
	v, err := oauthForm(r, "response_type client_id redirect_uri scope state nonce code_challenge code_challenge_method iwut_channel iwut_rpc_api_major prompt max_age")
	if err != nil || v.Get("response_type") != "code" {
		oauthError(w, d.ErrRequest)
		return
	}
	if !h.rate("client:"+v.Get("client_id"), oauthLimit(h.ClientPerMinute, 300)) {
		w.Header().Set("Retry-After", "60")
		oauthJSON(w, 429, map[string]string{"error": "slow_down"})
		return
	}
	major, e := strconv.ParseInt(v.Get("iwut_rpc_api_major"), 10, 32)
	if e != nil {
		oauthError(w, d.ErrRequest)
		return
	}
	scopes, e := d.ParseScopes(v.Get("scope"))
	if e != nil {
		oauthError(w, e)
		return
	}
	q := d.AuthorizationRequest{ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), Scopes: scopes, State: v.Get("state"), Nonce: v.Get("nonce"), Challenge: v.Get("code_challenge"), ChallengeMethod: v.Get("code_challenge_method"), Channel: v.Get("iwut_channel"), Major: int32(major), Prompt: v.Get("prompt")}
	if a, ok := v["max_age"]; ok {
		n, e := strconv.ParseInt(a[0], 10, 64)
		if e != nil || n < 0 || n > 315360000 {
			oauthError(w, d.ErrRequest)
			return
		}
		q.MaxAge = &n
	}
	out, e := h.Service.Begin(r.Context(), q, portalToken(r))
	if e != nil {
		oauthError(w, e)
		return
	}
	h.render(w, r, out)
}
func (h *OAuthHTTP) sameOrigin(r *http.Request) bool {
	return len(r.Header.Values("Origin")) == 1 && r.Header.Get("Origin") == h.Origin
}
func (h *OAuthHTTP) portalSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || !h.sameOrigin(r) || r.URL.RawQuery != "" || len(r.Header.Values("X-Iwut-Session")) != 1 {
		oauthError(w, d.ErrRequest)
		return
	}
	mt, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	b, err := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
	var body map[string]json.RawMessage
	if e != nil || mt != "application/json" || err != nil || len(b) > 16*1024 || json.Unmarshal(b, &body) != nil || body == nil || len(body) != 0 {
		oauthError(w, d.ErrRequest)
		return
	}
	raw := r.Header.Get("X-Iwut-Session")
	ss, err := h.Service.PortalSession(r.Context(), raw)
	if err != nil {
		oauthError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-iwut-portal", Value: raw, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: ss.ExpiresAt})
	oauthJSON(w, 200, map[string]bool{"authenticated": true})
}
func (h *OAuthHTTP) view(w http.ResponseWriter, r *http.Request) {
	v, e := oauthForm(r, "interaction")
	if e != nil || r.Method != "GET" {
		oauthError(w, d.ErrRequest)
		return
	}
	c, e := r.Cookie("__Host-iwut-interaction")
	if e != nil {
		oauthError(w, d.ErrRequest)
		return
	}
	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 || parts[0] != v.Get("interaction") {
		oauthError(w, d.ErrRequest)
		return
	}
	out, e := h.Service.View(r.Context(), parts[0], parts[1], portalToken(r))
	if e != nil {
		oauthError(w, e)
		return
	}
	h.render(w, r, out)
}
func (h *OAuthHTTP) confirm(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != "POST" || !h.sameOrigin(r) {
		oauthError(w, d.ErrRequest)
		return
	}
	v, e := oauthConsentForm(r)
	if e != nil {
		oauthError(w, e)
		return
	}
	if v.Get("interaction") != id {
		oauthError(w, d.ErrRequest)
		return
	}
	if v.Get("decision") != "approve" && v.Get("decision") != "deny" {
		oauthError(w, d.ErrRequest)
		return
	}
	scopes := []string{}
	if len(v["scope"]) != 0 {
		scopes = v["scope"]
		if !d.ValidScopes(scopes) {
			e = d.ErrScope
		}
		if e != nil {
			oauthError(w, e)
			return
		}
	}
	token := portalToken(r)
	session, err := h.Service.PortalSession(r.Context(), token)
	if err != nil {
		oauthError(w, err)
		return
	}
	if !h.rate(fmt.Sprintf("confirm:%x", sha256.Sum256([]byte(session.AuthID))), oauthLimit(h.UserConfirmPerMinute, 30)) {
		w.Header().Set("Retry-After", "60")
		oauthJSON(w, 429, map[string]string{"error": "slow_down"})
		return
	}
	target, e := h.Service.Confirm(r.Context(), v.Get("interaction"), v.Get("csrf"), token, scopes, v.Get("decision") == "approve")
	if e != nil {
		oauthError(w, e)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

type oauthConsentScope struct {
	Name, Label, Description string
	Required, Granted        bool
}

func oauthConsentForm(r *http.Request) (url.Values, error) {
	mt, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || mt != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		return nil, d.ErrRequest
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
	if e != nil || len(raw) > 16*1024 {
		return nil, d.ErrRequest
	}
	v, e := url.ParseQuery(string(raw))
	if e != nil {
		return nil, d.ErrRequest
	}
	for k, vs := range v {
		if k == "scope" {
			if !d.ValidScopes(vs) {
				return nil, d.ErrScope
			}
			continue
		}
		if len(vs) != 1 || k != "interaction" && k != "csrf" && k != "decision" {
			return nil, d.ErrRequest
		}
	}
	return v, nil
}

var oauthConsentTemplate = template.Must(template.New("consent").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>应用授权</title><body><main>{{if .View.LoginRequired}}<h1>登录平台账号</h1><p>登录完成后返回本页面继续授权，不会自动创建账号。</p><a href="{{.Login}}">前往官方登录页</a>{{else}}<h1>授权 {{.View.DisplayName}}</h1><p>开发者：{{.View.DeveloperHandle}} · 渠道：{{.View.Channel}}</p><p>此渠道的客户端共享授权。退出平台不会退出第三方应用。</p><form method="post" action="{{.Action}}"><input type="hidden" name="interaction" value="{{.View.InteractionID}}"><input type="hidden" name="csrf" value="{{.View.CSRF}}">{{range .Scopes}}<p><label>{{if .Required}}<input type="hidden" name="scope" value="{{.Name}}"><input type="checkbox" checked disabled>{{else}}<input type="checkbox" name="scope" value="{{.Name}}" {{if .Granted}}checked{{end}}>{{end}} {{.Label}}{{if .Required}}（必需）{{end}}{{if .Granted}}（已授权）{{end}}</label><br>{{.Description}}</p>{{end}}<button name="decision" value="approve">同意</button><button name="decision" value="deny">拒绝</button></form>{{end}}</main></body></html>`))

func (h *OAuthHTTP) render(w http.ResponseWriter, r *http.Request, v d.AuthorizationView) {
	if v.Redirect != "" {
		http.Redirect(w, r, v.Redirect, http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-iwut-interaction", Value: v.InteractionID + "." + v.CSRF, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	u, _ := url.Parse(h.Issuer)
	login, _ := url.Parse(h.LoginURL)
	q := login.Query()
	q.Set("return_to", u.Path+"/portal/interaction?interaction="+url.QueryEscape(v.InteractionID))
	login.RawQuery = q.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var scopes []oauthConsentScope
	for _, definition := range v.Definitions {
		if d.Contains(v.Requested, definition.Name) {
			scopes = append(scopes, oauthConsentScope{Name: definition.Name, Label: definition.Label, Description: definition.Description, Required: definition.Name == "openid" || d.Contains(v.Required, definition.Name), Granted: d.Contains(v.PreviouslyGranted, definition.Name)})
		}
	}
	_ = oauthConsentTemplate.Execute(w, struct {
		View          d.AuthorizationView
		Login, Action string
		Scopes        []oauthConsentScope
	}{v, login.String(), u.Path + "/portal/interactions/" + v.InteractionID + "/confirm", scopes})
}

func oauthLimit(configured, fallback int) int {
	if configured > 0 && configured < fallback {
		return configured
	}
	return fallback
}
