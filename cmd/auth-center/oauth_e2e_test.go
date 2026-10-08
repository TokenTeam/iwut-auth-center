package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	ip "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/identity"
	dp "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/oauth_delegation"
	gp "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/oauth_grant"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/oauthcrypto"
	"iwut-auth-center/internal/config"
	d "iwut-auth-center/internal/oauth/domain"
)

func TestOAuthE2E_ProductionWireActualAppProvider(t *testing.T) {
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	ctx := t.Context()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	writeJSON := func(name string, v any) string {
		data, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return write(name, data)
	}
	serviceKey, callers := testServiceCallerRegistry(t)
	der, _ := x509.MarshalPKIXPublicKey(&serviceKey.PublicKey)
	servicePEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	identityKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ = x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	publicFile := write("identity-public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	keyFile := func(name string, key *rsa.PrivateKey) string {
		return write(name, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	}
	oidcKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	delegationKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	raw, _ := base64.StdEncoding.DecodeString(callers)
	var registry map[string]map[string]any
	if e := json.Unmarshal(raw, &registry); e != nil {
		t.Fatal(e)
	}
	registry["gateway"] = map[string]any{"status": "ACTIVE", "keys": registry["app-center"]["keys"], "permissions": []string{"auth.identity.issue", "auth.oauth.delegation.issue"}, "identityAudiences": []string{"iwut-auth-center", "iwut-app-center"}}
	raw, _ = json.Marshal(registry)
	callers = base64.StdEncoding.EncodeToString(raw)
	keysJSON, _ := json.Marshal(map[string]string{"identity-k1": publicFile})
	dbName := "oauth_e2e_" + uuid.NewString()
	authHTTP, authGRPC, appGRPC := reserveAddress(t), reserveAddress(t), reserveAddress(t)
	env := map[string]string{config.UserEndpointsEnabledEnv: "true", config.IdentityIssuanceEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: authHTTP, config.GRPCAddrEnv: authGRPC, "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_ASSOC_KEY_VERSION": "v1", "AUTH_ASSOC_ENCRYPT_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "AUTH_ASSOC_LOOKUP_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "AUTH_PROFILE_CATALOG_FILE": write("profile.json", []byte(`{"definitions":[{"key":"basic.name","label":"Name","description":"User-provided display name","valueType":"STRING","constraints":{"maxLength":80}}]}`)), "AUTH_USER_IDENTITY_ISSUER": "identity-test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keysJSON), "AUTH_USER_IDENTITY_SIGNING_KID": "identity-k1", "AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(identityKey)}))}
	route := d.Route{ID: "resource-read", Audience: "resource-service", Protocol: "HTTP", Method: "GET", Path: "/items/{id}", Scopes: []string{"items.read"}, Channels: []string{"TEST", "STABLE", "GREY"}}
	policy := writeJSON("routes.json", map[string]any{"version": 1, "routes": []oauthRouteJSON{{ID: route.ID, Audience: route.Audience, Protocol: route.Protocol, Method: route.Method, Path: route.Path, Scopes: route.Scopes, Channels: route.Channels}, {ID: "stable-only", Audience: route.Audience, Protocol: "HTTP", Method: "GET", Path: "/stable/{id}", Scopes: route.Scopes, Channels: []string{"STABLE"}}}, "callers": map[string]any{"gateway": map[string]any{"routes": []string{route.ID, "stable-only"}, "audiences": []string{route.Audience}}}})
	clockFile := writeJSON("clock.json", map[string]any{"observedAt": time.Now().UTC(), "offsetMillis": 0})
	cfg := config.OAuth{ClockObservationFile: clockFile, ResourceScopesReady: true, Issuer: "https://auth.example.test/oidc", PortalOrigin: "https://auth.example.test", PortalLoginURL: "https://auth.example.test/login", SectorSuffix: "sectors.example.test", CatalogFile: writeJSON("scopes.json", []d.Scope{{Name: "openid", Label: "Login", Description: "Identify account", Kind: "PROTOCOL", Enabled: true}, {Name: "email", Label: "Email", Description: "Verified email", Kind: "PROTOCOL", Enabled: true}, {Name: "offline_access", Label: "Background", Description: "Refresh access", Kind: "PROTOCOL", Enabled: true}, {Name: "items.read", Label: "Items", Description: "Read items", Kind: "RESOURCE", Audience: "resource-service", Enabled: true}, {Name: "profile.basic.name", Label: "Name", Description: "Read user-provided name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name", Enabled: true}}), AppTarget: appGRPC, AppPlaintextLoopback: true, ServiceKeyID: "auth-service", ServiceKeyFile: keyFile("service.pem", serviceKey), OIDCKeyID: "oidc", OIDCKeyFile: keyFile("oidc.pem", oidcKey), DelegationKeyID: "delegation", DelegationKeyFile: keyFile("delegation.pem", delegationKey), RoutePolicyFile: policy, PublicEnabled: true, PortalReady: true, GatewayReady: true, RefreshEnabled: true}
	env["AUTH_CENTER_OAUTH_CONFIG_FILE"] = writeJSON("oauth.json", cfg)
	configuration, e := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if e != nil {
		t.Fatal(e)
	}
	dbClient, e := ma.NewClient(uri)
	if e != nil {
		t.Fatal(e)
	}
	db := dbClient.Database(dbName)
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = dbClient.Disconnect(context.Background()) })
	app, cleanup, e := wireApp(configuration)
	if e != nil {
		t.Fatal(e)
	}
	conn, stop := startUserApp(t, app, cleanup, authGRPC)
	defer stop()
	auth := authpb.NewAuthenticationServiceClient(conn)
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	user, _ := registerUser(t, auth, device, bytes.Repeat([]byte{11}, 32))
	device2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reviewer, _ := registerUser(t, auth, device2, bytes.Repeat([]byte{12}, 32))
	// Fixtures establish previously accepted enrollment/reviewer state; all App
	// registration, reviews, publication and Tester admission use production APIs.
	if _, e = db.Collection(ma.PrincipalCollection).UpdateOne(ctx, bson.M{"authId": user.AuthId}, bson.M{"$set": bson.M{"developerStatus": "APPROVED", "developerRevision": int64(1)}}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Collection("auth_developer_handles").InsertOne(ctx, bson.M{"authId": user.AuthId, "developerHandle": "oauthauthor"}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Collection(ma.EmailBindingCollection).InsertOne(ctx, bson.M{"authId": user.AuthId, "email": "student@example.test", "revision": int64(1), "verifiedAt": time.Now()}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Collection(ma.PrincipalCollection).UpdateOne(ctx, bson.M{"authId": user.AuthId}, bson.M{"$set": bson.M{"profile.entries": bson.A{bson.M{"key": "basic.name", "valueType": "STRING", "value": "OAuth Alice"}}, "profile.revision": int64(2), "profile.updatedAt": time.Now()}}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Collection(ma.PrincipalCollection).UpdateOne(ctx, bson.M{"authId": reviewer.AuthId}, bson.M{"$set": bson.M{"permissions": []string{"app.profile.review", "app.version.review"}, "permissionRevision": int64(1)}}); e != nil {
		t.Fatal(e)
	}
	gatewayToken, e := oauthcrypto.Sign(oauthcrypto.Key{ID: "app-center-2026-01", Private: serviceKey}, "JWT", map[string]any{"iss": "gateway", "sub": "gateway", "aud": "iwut-auth-center", "iat": time.Now().Unix(), "nbf": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "jti": uuid.NewString()})
	if e != nil {
		t.Fatal(e)
	}
	issue := func(u *authpb.UserRegistrationResult) string {
		t.Helper()
		r, e := ip.NewUserIdentityServiceClient(conn).IssueUserIdentityFromSession(metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+gatewayToken, "x-iwut-session", u.Session.SessionToken)), &ip.IssueUserIdentityFromSessionRequest{Audience: "iwut-app-center"})
		if e != nil {
			t.Fatal(e)
		}
		return r.IdentityJws
	}
	appRegistry, _ := json.Marshal(map[string]any{"iwut-auth-center": map[string]any{"status": "ACTIVE", "keys": map[string]any{"auth-service": map[string]string{"publicKeyPemB64": base64.StdEncoding.EncodeToString(servicePEM)}}, "permissions": []string{"app.oauth.client.read", "app.oauth.client.verify", "app.oauth.runtime.resolve", "app.oauth.context.resolve", "app.oauth.redirects.read"}}})
	_, appURL, _ := startActualApp(t, uri, publicFile, authGRPC, serviceKey, map[string]string{"APP_CENTER_GRPC_ADDR": appGRPC, "APP_CENTER_SERVICE_CALLERS_B64": base64.StdEncoding.EncodeToString(appRegistry)})
	appCall := func(method, path, token string, body any) map[string]any {
		t.Helper()
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req, e := http.NewRequestWithContext(ctx, method, appURL+path, bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Iwut-Identity", token)
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		payload, _ := io.ReadAll(res.Body)
		if res.StatusCode < 200 || res.StatusCode > 299 {
			t.Fatalf("App %s %s: %d %s", method, path, res.StatusCode, payload)
		}
		var out map[string]any
		if e = json.Unmarshal(payload, &out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	ownerToken, reviewToken := issue(user), issue(reviewer)
	created := appCall("POST", "/v1/applications", ownerToken, map[string]any{"name": "OAuthWireExample"})
	applicationID := created["id"].(string)
	prefix := "/v1/applications/" + applicationID
	profile := appCall("POST", prefix+"/profile-revisions", ownerToken, map[string]any{"displayName": "OAuth Example", "description": "Integration fixture", "icon": nil})
	profileID := profile["profileRevisionId"].(string)
	submitted := appCall("POST", prefix+"/profile-revisions/"+profileID+"/reviews", ownerToken, map[string]any{"expectedRevision": "1"})
	reviewID := submitted["review"].(map[string]any)["profileReviewId"].(string)
	appCall("POST", prefix+"/profile-revisions/"+profileID+"/reviews/"+reviewID+"/decision", reviewToken, map[string]any{"expectedProfileRevisionRevision": "2", "expectedCurrentPublishedProfileRevisionId": nil, "expectedPolicyVersion": "app-profile-review-v1", "outcome": "APPROVE", "confirmedCheckIds": []string{"content-policy-reviewed", "icon-content-reviewed"}})
	callback := "https://www.whut.edu.cn/oauth-callback"
	version := appCall("POST", prefix+"/versions", ownerToken, map[string]any{"versionLabel": "1.0", "launchUrl": "https://www.whut.edu.cn/", "rpcApiMinVersion": 1, "rpcApiMaxVersionExclusive": 2, "requiredCapabilities": []string{}, "requiredScopes": []string{"openid"}, "optionalScopes": []string{"email", "offline_access", "items.read", "profile.basic.name"}, "oauthRedirects": map[string]any{"pkceRedirectUris": []string{callback}, "confidentialRedirectUris": []string{callback + "-confidential"}}})
	versionID := version["versionId"].(string)
	vr := appCall("POST", prefix+"/versions/"+versionID+"/reviews", ownerToken, map[string]any{"expectedRevision": "1"})
	vrID := vr["review"].(map[string]any)["reviewId"].(string)
	appCall("POST", prefix+"/versions/"+versionID+"/reviews/"+vrID+"/decision", reviewToken, map[string]any{"outcome": "APPROVE", "expectedPolicyVersion": "app-version-review-v2", "confirmedCheckIds": []string{"content-policy-reviewed", "launch-url-content-reviewed", "requested-access-reviewed", "oauth-redirects-reviewed"}})
	registration := appCall("POST", prefix+"/oauth-registrations/OAUTH_CHANNEL_TEST/clients", ownerToken, map[string]any{"type": "OAUTH_CLIENT_TYPE_PUBLIC_PKCE"})
	clientID := registration["registration"].(map[string]any)["publicClient"].(map[string]any)["clientId"].(string)
	secretRegistration := appCall("POST", prefix+"/oauth-registrations/OAUTH_CHANNEL_TEST/clients", ownerToken, map[string]any{"type": "OAUTH_CLIENT_TYPE_CONFIDENTIAL_SECRET", "expectedRegistrationRevision": "1"})
	secretID := secretRegistration["registration"].(map[string]any)["confidentialClient"].(map[string]any)["clientId"].(string)
	secret := secretRegistration["clientSecret"].(string)
	clientChannels := map[string]string{clientID: "TEST", secretID: "TEST"}
	clientSecrets := map[string]string{secretID: secret}
	publicClients := map[string]string{"TEST": clientID}
	privateClients := map[string]string{"TEST": secretID}
	for _, channel := range []string{"STABLE", "GREY"} {
		path := prefix + "/oauth-registrations/OAUTH_CHANNEL_" + channel + "/clients"
		registered := appCall("POST", path, ownerToken, map[string]any{"type": "OAUTH_CLIENT_TYPE_PUBLIC_PKCE"})
		id := registered["registration"].(map[string]any)["publicClient"].(map[string]any)["clientId"].(string)
		publicClients[channel], clientChannels[id] = id, channel
		registered = appCall("POST", path, ownerToken, map[string]any{"type": "OAUTH_CLIENT_TYPE_CONFIDENTIAL_SECRET", "expectedRegistrationRevision": "1"})
		id = registered["registration"].(map[string]any)["confidentialClient"].(map[string]any)["clientId"].(string)
		privateClients[channel], clientChannels[id] = id, channel
		clientSecrets[id] = registered["clientSecret"].(string)
	}
	publication := appCall("PUT", prefix+"/publications/1/test-slot", ownerToken, map[string]any{"versionId": versionID})
	publicationRevision := publication["publication"].(map[string]any)["revision"].(string)
	updatePublication := func(method, slot string, body any) {
		t.Helper()
		result := appCall(method, prefix+"/publications/1/"+slot, issue(user), body)
		publicationRevision = result["publication"].(map[string]any)["revision"].(string)
	}
	setStable := func() {
		updatePublication("PUT", "stable-slot", map[string]any{"versionId": versionID, "expectedPublicationRevision": publicationRevision})
	}
	setGrey := func(exposure int) {
		updatePublication("PUT", "grey-rollout", map[string]any{"versionId": versionID, "exposureBasisPoints": exposure, "expectedPublicationRevision": publicationRevision})
	}
	clearGrey := func() {
		updatePublication("DELETE", "grey-rollout?expected_publication_revision="+publicationRevision, nil)
	}
	clearStable := func() {
		updatePublication("DELETE", "stable-slot?expected_publication_revision="+publicationRevision, nil)
	}
	setStable()
	setGrey(10000)
	link := appCall("POST", prefix+"/tester-join-links", ownerToken, map[string]any{})
	linkURL, _ := url.Parse(link["joinUrl"].(string))
	fragment, _ := url.ParseQuery(linkURL.Fragment)
	appCall("POST", "/v1/tester-join-links/"+fragment.Get("joinLinkId")+"/memberships", ownerToken, map[string]any{"secret": fragment.Get("secret")})

	base := "http://" + authHTTP + "/oidc"
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 10 * time.Second}
	request := func(method, path, body, ctype string, headers http.Header) (int, http.Header, []byte) {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header = headers.Clone()
		if r.Header == nil {
			r.Header = http.Header{}
		}
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		resp, e := httpClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, b
	}
	code, headers, body := request("POST", "/portal/session", "{}", "application/json", http.Header{"Origin": []string{cfg.PortalOrigin}, "X-Iwut-Session": []string{user.Session.SessionToken}})
	if code != 200 || !strings.Contains(headers.Get("Set-Cookie"), "HttpOnly") {
		t.Fatal("portal bridge", code, string(body))
	}
	cookie := "__Host-iwut-portal=" + user.Session.SessionToken
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := strings.Repeat("a", 43)
	nonce := strings.Repeat("b", 43)
	authorizeQuery := func(client string) url.Values {
		redirect := callback
		if _, confidential := clientSecrets[client]; confidential {
			redirect += "-confidential"
		}
		return url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {redirect}, "scope": {"openid email offline_access items.read profile.basic.name"}, "state": {state}, "nonce": {nonce}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "iwut_channel": {clientChannels[client]}, "iwut_rpc_api_major": {"1"}, "prompt": {"consent"}}
	}
	for _, wrongChannel := range []string{"STABLE", "GREY", "UNKNOWN"} {
		q := authorizeQuery(clientID)
		q.Set("iwut_channel", wrongChannel)
		status, headers, _ := request("GET", "/authorize?"+q.Encode(), "", "", http.Header{"Cookie": []string{cookie}})
		if status != 400 || headers.Get("Location") != "" {
			t.Fatal("client channel substitution accepted", wrongChannel, status)
		}
	}
	authorize := func(client string) string {
		t.Helper()
		q := authorizeQuery(client)
		status, _, b := request("GET", "/authorize?"+q.Encode(), "", "", http.Header{"Cookie": []string{cookie}})
		if status != 200 {
			t.Fatal("authorize", status, string(b))
		}
		field := func(name string) string {
			m := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindSubmatch(b)
			if len(m) != 2 {
				t.Fatalf("missing consent field %s: %s", name, b)
			}
			return string(m[1])
		}
		id, csrf := field("interaction"), field("csrf")
		v := url.Values{"interaction": {id}, "csrf": {csrf}, "decision": {"approve"}, "scope": {"openid", "email", "offline_access", "items.read", "profile.basic.name"}}
		status, h, b := request("POST", "/portal/interactions/"+id+"/confirm", v.Encode(), "application/x-www-form-urlencoded", http.Header{"Cookie": []string{cookie}, "Origin": []string{cfg.PortalOrigin}})
		if status != 303 {
			t.Fatal("confirm", status, string(b))
		}
		u, _ := url.Parse(h.Get("Location"))
		if u.Query().Get("state") != state || u.Query().Get("iss") != cfg.Issuer {
			t.Fatal("callback binding")
		}
		return u.Query().Get("code")
	}
	exchange := func(client string, basic bool) map[string]any {
		c := authorize(client)
		redirect := callback
		if basic {
			redirect += "-confidential"
		}
		v := url.Values{"grant_type": {"authorization_code"}, "code": {c}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
		h := http.Header{}
		if !basic {
			h.Set("Origin", "https://www.whut.edu.cn")
		}
		if basic {
			h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(client)+":"+url.QueryEscape(clientSecrets[client]))))
		} else {
			v.Set("client_id", client)
		}
		status, _, b := request("POST", "/token", v.Encode(), "application/x-www-form-urlencoded", h)
		if status != 200 {
			t.Fatal("exchange", status, string(b))
		}
		var out map[string]any
		if json.Unmarshal(b, &out) != nil {
			t.Fatal("invalid token response")
		}
		return out
	}
	tokens := exchange(clientID, false)
	secretTokens := exchange(secretID, true)
	idToken := tokens["id_token"].(string)
	parts := strings.Split(idToken, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&oidcKey.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		t.Fatal("invalid OIDC signature")
	}
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	if claims["aud"] != clientID || claims["nonce"] != nonce || claims["iss"] != cfg.Issuer || claims["sub"] == user.AuthId {
		t.Fatal("invalid OIDC claims")
	}
	access := tokens["access_token"].(string)
	clientContext := oidc.ClientContext(ctx, &http.Client{Transport: oauthIssuerTransport{host: authHTTP}, Timeout: 5 * time.Second})
	provider, e := oidc.NewProvider(clientContext, cfg.Issuer)
	if e != nil {
		t.Fatal("OIDC discovery interoperability", e)
	}
	verified, e := provider.Verifier(&oidc.Config{ClientID: clientID, SupportedSigningAlgs: []string{"RS256"}}).Verify(clientContext, idToken)
	if e != nil || verified.Nonce != nonce || verified.VerifyAccessToken(access) != nil {
		t.Fatal("OIDC client verification", e)
	}
	userInfo, e := provider.UserInfo(clientContext, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: access, TokenType: "Bearer"}))
	if e != nil || userInfo.Subject != verified.Subject {
		t.Fatal("OIDC UserInfo interoperability", e)
	}

	accessHash := sha256.Sum256([]byte(access))
	if claims["at_hash"] != base64.RawURLEncoding.EncodeToString(accessHash[:16]) {
		t.Fatal("at_hash")
	}
	code, _, body = request("GET", "/userinfo", "", "", http.Header{"Authorization": []string{"Bearer " + access}})
	if code != 200 || !bytes.Contains(body, []byte("student@example.test")) || !bytes.Contains(body, []byte(`"iwut_profile":{"basic.name":"OAuth Alice"}`)) || bytes.Contains(body, []byte(user.AuthId)) {
		t.Fatal("userinfo", code, string(body))
	}
	code, _, body = request("GET", "/userinfo?access_token="+access, "", "", nil)
	if code != 400 {
		t.Fatal("URL token accepted", code)
	}
	grants, e := gp.NewOAuthGrantServiceClient(conn).ListOwnApplicationGrants(sessionCallContext(ctx, user.Session.SessionToken), &gp.ListOwnApplicationGrantsRequest{})
	if e != nil || len(grants.Grants) != 1 {
		t.Fatal("shared consent", grants, e)
	}
	policyRuntime, e := loadOAuthRoutes(policy, nil)
	if e != nil {
		t.Fatal(e)
	}
	_ = writeJSON("clock.json", map[string]any{"observedAt": time.Now().UTC(), "offsetMillis": 0})
	delegation, e := dp.NewOAuthDelegationServiceClient(conn).IssueDelegationContext(metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+gatewayToken, "x-iwut-access-token", access)), &dp.IssueDelegationContextRequest{RouteId: route.ID, PolicyDigest: policyRuntime.Digest, Protocol: "HTTP", Method: "GET", TargetPath: "/items/123"})
	if e != nil || delegation.DelegationToken == "" {
		t.Fatal("delegation", e)
	}
	if _, e = dp.NewOAuthDelegationServiceClient(conn).IssueDelegationContext(ctx, &dp.IssueDelegationContextRequest{}); status.Code(e) != codes.Unauthenticated {
		t.Fatal("anonymous delegation", e)
	}
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "client_id": {clientID}}
	code, _, body = request("POST", "/token", refresh.Encode(), "application/x-www-form-urlencoded", nil)
	if code != 200 {
		t.Fatal("refresh", code, string(body))
	}
	// Publishing other channels must not break the existing TEST sector lookup.
	// One application has one subject, but independent channel grants.
	channelTokens := map[string][]map[string]any{}
	for _, channel := range []string{"STABLE", "GREY"} {
		for _, confidential := range []bool{false, true} {
			id := publicClients[channel]
			if confidential {
				id = privateClients[channel]
			}
			issued := exchange(id, confidential)
			verifiedOther, err := provider.Verifier(&oidc.Config{ClientID: id}).Verify(clientContext, issued["id_token"].(string))
			if err != nil || verifiedOther.Subject != verified.Subject {
				t.Fatal("cross-channel subject", channel, err)
			}
			issued["client_id"] = id
			channelTokens[channel] = append(channelTokens[channel], issued)
		}
	}
	allGrants, err := gp.NewOAuthGrantServiceClient(conn).ListOwnApplicationGrants(sessionCallContext(ctx, user.Session.SessionToken), &gp.ListOwnApplicationGrantsRequest{})
	if err != nil || len(allGrants.Grants) != 3 {
		t.Fatal("channel grants not isolated", err)
	}
	delegate := func(token, routeID string) error {
		_ = writeJSON("clock.json", map[string]any{"observedAt": time.Now().UTC(), "offsetMillis": 0})
		path := "/items/123"
		if routeID == "stable-only" {
			path = "/stable/123"
		}
		_, err := dp.NewOAuthDelegationServiceClient(conn).IssueDelegationContext(metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+gatewayToken, "x-iwut-access-token", token)), &dp.IssueDelegationContextRequest{RouteId: routeID, PolicyDigest: policyRuntime.Digest, Protocol: "HTTP", Method: "GET", TargetPath: path})
		return err
	}
	for _, channel := range []string{"STABLE", "GREY"} {
		for _, issued := range channelTokens[channel] {
			if err := delegate(issued["access_token"].(string), route.ID); err != nil {
				t.Fatal(channel, "delegation", err)
			}
			err := delegate(issued["access_token"].(string), "stable-only")
			if channel == "STABLE" && err != nil || channel == "GREY" && status.Code(err) != codes.PermissionDenied {
				t.Fatal("route channel boundary", channel, err)
			}
		}
	}
	if err := delegate(access, "stable-only"); status.Code(err) != codes.PermissionDenied {
		t.Fatal("TEST entered STABLE route", err)
	}
	infoStatus := func(token string) int {
		code, _, _ := request("GET", "/userinfo", "", "", http.Header{"Authorization": []string{"Bearer " + token}})
		return code
	}
	rotate := func(issued map[string]any, want int) {
		t.Helper()
		id := issued["client_id"].(string)
		values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued["refresh_token"].(string)}}
		h := http.Header{}
		if secret, confidential := clientSecrets[id]; confidential {
			h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret))))
		} else {
			values.Set("client_id", id)
		}
		code, _, body := request("POST", "/token", values.Encode(), "application/x-www-form-urlencoded", h)
		if code != want {
			t.Fatal("channel refresh", clientChannels[id], code, string(body))
		}
		if want == 200 {
			var next map[string]any
			if json.Unmarshal(body, &next) != nil {
				t.Fatal("invalid refresh response")
			}
			issued["access_token"], issued["refresh_token"] = next["access_token"], next["refresh_token"]
		} else if !bytes.Contains(body, []byte("invalid_grant")) {
			t.Fatal("wrong failed refresh response", string(body))
		}
	}
	for _, issued := range append(channelTokens["STABLE"], channelTokens["GREY"]...) {
		rotate(issued, 200)
	}
	// A real non-Tester can use STABLE and a fully exposed GREY rollout.
	cookie = "__Host-iwut-portal=" + reviewer.Session.SessionToken
	nonTesterQuery := authorizeQuery(clientID)
	denied, _, _ := request("GET", "/authorize?"+nonTesterQuery.Encode(), "", "", http.Header{"Cookie": []string{cookie}})
	if denied != 400 {
		t.Fatal("non-Tester TEST authorization", denied)
	}
	nonTesterStable := exchange(publicClients["STABLE"], false)
	nonTesterGrey := exchange(publicClients["GREY"], false)
	nonTesterGrey["client_id"] = publicClients["GREY"]
	cookie = "__Host-iwut-portal=" + user.Session.SessionToken
	if infoStatus(nonTesterStable["access_token"].(string)) != 200 || infoStatus(nonTesterGrey["access_token"].(string)) != 200 {
		t.Fatal("non-Tester rejected")
	}
	// Shrink the actual cohort. In the rare case this non-Tester occupies bucket
	// zero, choose another real registered user, without modifying App facts.
	setGrey(1)
	for attempt := 0; infoStatus(nonTesterGrey["access_token"].(string)) == 200; attempt++ {
		if attempt >= 8 {
			t.Fatal("could not select a user outside one-basis-point cohort")
		}
		device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		association := make([]byte, 32)
		if _, err := rand.Read(association); err != nil {
			t.Fatal(err)
		}
		other, _ := registerUser(t, auth, device, association)
		setGrey(10000)
		cookie = "__Host-iwut-portal=" + other.Session.SessionToken
		nonTesterGrey = exchange(publicClients["GREY"], false)
		nonTesterGrey["client_id"] = publicClients["GREY"]
		cookie = "__Host-iwut-portal=" + user.Session.SessionToken
		setGrey(1)
	}
	if infoStatus(nonTesterGrey["access_token"].(string)) != 401 {
		t.Fatal("grey cohort loss not rejected")
	}
	rotate(nonTesterGrey, 400)
	if err := delegate(nonTesterGrey["access_token"].(string), route.ID); status.Code(err) != codes.Unauthenticated {
		t.Fatal("grey cohort delegation", err)
	}
	setGrey(10000)
	rotate(nonTesterGrey, 200)
	// Code binds the old publication tuple even when its channel returns later.
	staleCode := authorize(publicClients["GREY"])
	clearGrey()
	for _, issued := range channelTokens["GREY"] {
		if infoStatus(issued["access_token"].(string)) != 401 {
			t.Fatal("cleared GREY still accepted")
		}
		rotate(issued, 400)
	}
	for _, issued := range channelTokens["STABLE"] {
		if infoStatus(issued["access_token"].(string)) != 200 {
			t.Fatal("GREY clear affected STABLE")
		}
	}
	setGrey(10000)
	staleValues := url.Values{"grant_type": {"authorization_code"}, "client_id": {publicClients["GREY"]}, "code": {staleCode}, "redirect_uri": {callback}, "code_verifier": {verifier}}
	code, _, body = request("POST", "/token", staleValues.Encode(), "application/x-www-form-urlencoded", nil)
	if code != 400 || !bytes.Contains(body, []byte("invalid_grant")) {
		t.Fatal("stale publication code accepted", code, string(body))
	}
	for _, issued := range channelTokens["GREY"] {
		rotate(issued, 200)
	}
	clearGrey()
	clearStable()
	for _, issued := range channelTokens["STABLE"] {
		if infoStatus(issued["access_token"].(string)) != 401 {
			t.Fatal("cleared STABLE still accepted")
		}
		rotate(issued, 400)
		if err := delegate(issued["access_token"].(string), route.ID); status.Code(err) != codes.Unauthenticated {
			t.Fatal("cleared STABLE delegation", err)
		}
	}
	setStable()
	setGrey(10000)
	for _, issued := range channelTokens["STABLE"] {
		rotate(issued, 200)
	}
	g := grants.Grants[0]
	if _, e = gp.NewOAuthGrantServiceClient(conn).RevokeOwnApplicationGrant(sessionCallContext(ctx, user.Session.SessionToken), &gp.RevokeOwnApplicationGrantRequest{GrantId: g.GrantId, ExpectedRevision: &g.Revision, Mode: gp.RevocationMode_REVOCATION_MODE_ALL}); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{access, secretTokens["access_token"].(string)} {
		code, _, body = request("GET", "/userinfo", "", "", http.Header{"Authorization": []string{"Bearer " + v}})
		if code != 401 {
			t.Fatal("revoked shared grant", code, string(body))
		}
	}
	for _, issued := range append(channelTokens["STABLE"], channelTokens["GREY"]...) {
		if infoStatus(issued["access_token"].(string)) != 200 {
			t.Fatal("TEST grant revocation affected another channel")
		}
	}
	t.Log("Actual Auth Wire + App019: reviewed runtime, both client types, consent, OIDC, refresh, UserInfo, delegation and shared revocation")
}

type oauthIssuerTransport struct{ host string }

func (t oauthIssuerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "auth.example.test" {
		return nil, fmt.Errorf("unexpected OIDC target")
	}
	copy := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = "http"
	u.Host = t.host
	copy.URL = &u
	return http.DefaultTransport.RoundTrip(copy)
}
