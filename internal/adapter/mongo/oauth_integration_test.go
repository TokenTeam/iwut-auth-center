package mongo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/oauthcrypto"
	d "iwut-auth-center/internal/oauth/domain"
	p "iwut-auth-center/internal/oauth/port"
	uc "iwut-auth-center/internal/oauth/usecase"
)

type oauthAppFixture struct {
	mu      sync.Mutex
	runtime d.Runtime
	fail    error
}

func (f *oauthAppFixture) Client(_ context.Context, id string) (d.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return d.Client{}, f.fail
	}
	c := f.runtime.Client
	c.ID = id
	if id == "secret-client" {
		c.Type = "CONFIDENTIAL_SECRET"
		c.CredentialRevision = 1
	}
	return c, nil
}
func (f *oauthAppFixture) VerifySecret(_ context.Context, c d.Client, secret string) (bool, error) {
	return secret == "secret", nil
}
func (f *oauthAppFixture) Runtime(_ context.Context, c d.Client, major int32) (d.Runtime, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return d.Runtime{}, f.fail
	}
	r := f.runtime
	r.Client = c
	r.Major = major
	r.ObservedAt = time.Now()
	r.ValidUntil = r.ObservedAt.Add(5 * time.Second)
	return r, nil
}
func (f *oauthAppFixture) Authorize(ctx context.Context, old d.Runtime, id string) (d.Runtime, error) {
	r, e := f.Runtime(ctx, old.Client, old.Major)
	if e != nil {
		return r, e
	}
	if r.VersionID != old.VersionID || r.ProfileID != old.ProfileID || r.PublicationRevision != old.PublicationRevision {
		return r, d.ErrGrant
	}
	return r, nil
}
func (f *oauthAppFixture) Redirects(ctx context.Context, id string) (d.RedirectSnapshot, error) {
	c, e := f.Client(ctx, "public-client")
	if e != nil {
		return d.RedirectSnapshot{}, e
	}
	r, e := f.Runtime(ctx, c, 1)
	return d.RedirectSnapshot{ApplicationID: id, Entries: []d.RedirectEntry{{Channel: "TEST", Major: 1, VersionID: r.VersionID, PublicationRevision: r.PublicationRevision}, {Channel: "TEST", Major: 2, VersionID: r.VersionID, PublicationRevision: r.PublicationRevision}}, URIs: r.Redirects, ObservedAt: r.ObservedAt, ValidUntil: r.ValidUntil}, e
}

type oauthFixture struct {
	auth                authenticationFixture
	session             string
	repo                *OAuthRepository
	app                 *oauthAppFixture
	service             *uc.Service
	crypto              *oauthcrypto.Crypto
	seed                []d.Scope
	verifier, challenge string
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	f := newAuthenticationFixture(t)
	db := f.r.database
	ctx := t.Context()
	if e := EnsureOAuthSchema(ctx, db); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"developerStatus": "APPROVED", "developerRevision": int64(1)}}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Collection("auth_developer_handles").InsertOne(ctx, bson.M{"authId": f.c.AuthID, "developerHandle": "testdev"}); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Collection(EmailBindingCollection).InsertOne(ctx, bindingDocument{AuthID: f.c.AuthID, Email: "student@example.test", Revision: 1, VerifiedAt: time.Now()}); e != nil {
		t.Fatal(e)
	}
	session := f.login(t).SessionToken
	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	crypto, e := oauthcrypto.New(oauthcrypto.Key{ID: "oidc", Private: k1}, oauthcrypto.Key{ID: "delegation", Private: k2}, nil)
	if e != nil {
		t.Fatal(e)
	}
	app := &oauthAppFixture{runtime: d.Runtime{Client: d.Client{ID: "public-client", ApplicationID: "app-one", Type: "PUBLIC_PKCE", Channel: "TEST", RegistrationRevision: 1, AuthorizationEpoch: 1}, Major: 1, AdminID: f.c.AuthID, VersionID: "version-one", ProfileID: "profile-one", DisplayName: "Test App", TesterID: "membership-one", PublicationRevision: 1, Redirects: []string{"https://client.example.test/callback"}, Required: []string{"openid"}, Optional: []string{"email", "offline_access", "data.read"}}}
	repo := NewOAuthRepository(f.r, db)
	seed := []d.Scope{{Name: "openid", Label: "登录", Description: "识别账号", Kind: "PROTOCOL", Enabled: true}, {Name: "email", Label: "邮箱", Description: "读取已验证邮箱", Kind: "PROTOCOL", Enabled: true}, {Name: "offline_access", Label: "后台访问", Description: "允许续签", Kind: "PROTOCOL", Enabled: true}, {Name: "data.read", Label: "读取", Description: "读取测试资源", Kind: "RESOURCE", Audience: "data-service", Enabled: true}}
	if e := repo.SeedCatalog(ctx, seed); e != nil {
		t.Fatal(e)
	}
	service, e := uc.New(repo, app, crypto, uc.Config{Issuer: "https://auth.example.test/oidc", SectorSuffix: "sectors.example.test", RefreshEnabled: true, SigningHealthy: func() bool { return true }})
	if e != nil {
		t.Fatal(e)
	}
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	return &oauthFixture{f, session, repo, app, service, crypto, seed, verifier, base64.RawURLEncoding.EncodeToString(sum[:])}
}
func (f *oauthFixture) begin(t *testing.T, scopes []string, client string, major int32) d.AuthorizationView {
	t.Helper()
	state, _ := f.crypto.Random()
	nonce, _ := f.crypto.Random()
	q := d.AuthorizationRequest{ClientID: client, RedirectURI: f.app.runtime.Redirects[0], State: state, Nonce: nonce, Challenge: f.challenge, ChallengeMethod: "S256", Channel: "TEST", Major: major, Prompt: "consent", Scopes: scopes}
	out, e := f.service.Begin(t.Context(), q, f.session)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func (f *oauthFixture) code(t *testing.T, scopes []string, client string) string {
	t.Helper()
	v := f.begin(t, scopes, client, 1)
	target, e := f.service.Confirm(t.Context(), v.InteractionID, v.CSRF, f.session, scopes, true)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(target)
	if u.Query().Get("code") == "" || u.Query().Get("iss") == "" {
		t.Fatal("invalid redirect")
	}
	return u.Query().Get("code")
}
func (f *oauthFixture) tokens(t *testing.T, scopes ...string) d.TokenResponse {
	t.Helper()
	code := f.code(t, scopes, "public-client")
	v, e := f.service.Exchange(t.Context(), d.ClientProof{ClientID: "public-client"}, code, f.app.runtime.Redirects[0], f.verifier)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func TestOAuthMongoAccessRecordBinding(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	for _, field := range []string{"data.authid", "data.grantid", "data.runtime.client.id"} {
		t.Run(field, func(t *testing.T) {
			token := f.tokens(t, "openid")
			_, err := f.repo.db.Collection("auth_oauth_access").UpdateOne(ctx,
				bson.M{"_id": f.crypto.Digest("access", token.AccessToken)},
				bson.M{"$set": bson.M{field: "different-owner"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.UserInfo(ctx, token.AccessToken); !errors.Is(err, d.ErrToken) {
				t.Fatal("mismatched token snapshot accepted", err)
			}
		})
	}
	token := f.tokens(t, "openid")
	_, err := f.repo.db.Collection("auth_oauth_access").UpdateOne(ctx,
		bson.M{"_id": f.crypto.Digest("access", token.AccessToken)},
		bson.M{"$unset": bson.M{"data.revoked": ""}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.UserInfo(ctx, token.AccessToken); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("missing revocation state accepted", err)
	}
}

func TestOAuthMongoLifecycleAndRevocation(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	tokens := f.tokens(t, "openid", "email", "offline_access", "data.read")
	info, e := f.service.UserInfo(ctx, tokens.AccessToken)
	if e != nil || info.Subject == "" || info.Subject == f.auth.c.AuthID || info.Email != "student@example.test" {
		t.Fatal(info, e)
	}
	rotated, e := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, tokens.RefreshToken, nil)
	if e != nil || rotated.RefreshToken == tokens.RefreshToken || rotated.IDToken != "" {
		t.Fatal(e)
	}
	if _, e = f.service.UserInfo(ctx, tokens.AccessToken); e != nil {
		t.Fatal("rotation invalidated access", e)
	}
	route := d.Route{ID: "read", Audience: "data-service", Protocol: "HTTP", Method: "GET", Path: "/data/{id}", Scopes: []string{"data.read"}, Channels: []string{"TEST"}}
	delegation, e := f.service.Delegate(ctx, rotated.AccessToken, d.DelegationRequest{RouteID: "read", PolicyDigest: "digest", Protocol: "HTTP", Method: "GET", TargetPath: "/data/123"}, route, "digest")
	if e != nil || delegation.Token == "" {
		t.Fatal(e)
	}
	if _, e = f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, tokens.RefreshToken, nil); !errors.Is(e, d.ErrGrant) {
		t.Fatal(e)
	}
	if _, e = f.service.UserInfo(ctx, rotated.AccessToken); !errors.Is(e, d.ErrToken) {
		t.Fatal("replay did not revoke family", e)
	}
	second := f.tokens(t, "openid", "email")
	grants, e := f.service.ListGrants(ctx, f.session, "", 50)
	if e != nil || len(grants) != 1 {
		t.Fatal(grants, e)
	}
	g := grants[0]
	v := f.begin(t, []string{"openid", "email"}, "public-client", 1)
	revoked, e := f.service.RevokeGrant(ctx, f.session, g.ID, g.Revision, false, []string{"email"})
	if e != nil || revoked.RevocationEpoch != g.RevocationEpoch+1 {
		t.Fatal(e)
	}
	if _, e = f.service.Confirm(ctx, v.InteractionID, v.CSRF, f.session, []string{"openid", "email"}, true); !errors.Is(e, d.ErrConflict) {
		t.Fatal("stale consent", e)
	}
	if _, e = f.service.UserInfo(ctx, second.AccessToken); !errors.Is(e, d.ErrToken) {
		t.Fatal(e)
	}
	third := f.tokens(t, "openid", "email")
	after, e := f.service.UserInfo(ctx, third.AccessToken)
	if e != nil || after.Subject != info.Subject {
		t.Fatal("pairwise mapping changed", e)
	}
	if _, e = f.service.UserInfo(ctx, second.AccessToken); !errors.Is(e, d.ErrToken) {
		t.Fatal("old epoch revived", e)
	}
	if e = f.service.RevokeToken(ctx, d.ClientProof{ClientID: "public-client"}, third.AccessToken, "refresh_token"); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.UserInfo(ctx, third.AccessToken); !errors.Is(e, d.ErrToken) {
		t.Fatal(e)
	}
}

func TestOAuthMongoApplicationClosureTombstoneBlocksEveryOnlinePath(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	if err := EnsureApplicationClosureSchema(ctx, f.repo.db); err != nil {
		t.Fatal(err)
	}
	tokens := f.tokens(t, "openid", "offline_access", "data.read")
	code := f.code(t, []string{"openid"}, "public-client")
	repository, _ := NewApplicationClosureRepository(f.auth.r)
	started := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := repository.Apply(ctx, "app-one", uuid.NewString(), started, uuid.NewString(), "app-center", started); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Begin(ctx, d.AuthorizationRequest{ClientID: "public-client", RedirectURI: f.app.runtime.Redirects[0], State: strings.Repeat("a", 43), Nonce: strings.Repeat("b", 43), Challenge: f.challenge, ChallengeMethod: "S256", Channel: "TEST", Major: 1, Prompt: "consent", Scopes: []string{"openid"}}, f.session); !errors.Is(err, d.ErrGrant) {
		t.Fatalf("authorize = %v", err)
	}
	if _, err := f.service.Exchange(ctx, d.ClientProof{ClientID: "public-client"}, code, f.app.runtime.Redirects[0], f.verifier); !errors.Is(err, d.ErrGrant) {
		t.Fatalf("exchange = %v", err)
	}
	if _, err := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, tokens.RefreshToken, nil); !errors.Is(err, d.ErrGrant) {
		t.Fatalf("refresh = %v", err)
	}
	if _, err := f.service.UserInfo(ctx, tokens.AccessToken); !errors.Is(err, d.ErrToken) {
		t.Fatalf("userinfo = %v", err)
	}
	if _, err := f.service.AccessClient(ctx, tokens.AccessToken); !errors.Is(err, d.ErrToken) {
		t.Fatalf("introspection = %v", err)
	}
	route := d.Route{ID: "read", Audience: "data-service", Protocol: "HTTP", Method: "GET", Path: "/data/{id}", Scopes: []string{"data.read"}, Channels: []string{"TEST"}}
	if _, err := f.service.Delegate(ctx, tokens.AccessToken, d.DelegationRequest{RouteID: "read", PolicyDigest: "digest", Protocol: "HTTP", Method: "GET", TargetPath: "/data/123"}, route, "digest"); !errors.Is(err, d.ErrToken) {
		t.Fatalf("delegation = %v", err)
	}
	grants, err := f.service.ListGrants(ctx, f.session, "", 50)
	if err != nil || len(grants) != 0 {
		t.Fatalf("grants = %#v, %v", grants, err)
	}
	if err = f.service.RevokeToken(ctx, d.ClientProof{ClientID: "public-client"}, tokens.AccessToken, "access_token"); err != nil {
		t.Fatalf("revoke = %v", err)
	}
}
func TestOAuthMongoCatalogCeilingAndAtomicity(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	tokens := f.tokens(t, "openid", "email", "offline_access")
	f.seed[1].Enabled = false
	if e := f.repo.SeedCatalog(ctx, f.seed); e != nil {
		t.Fatal(e)
	}
	info, e := f.service.UserInfo(ctx, tokens.AccessToken)
	if e != nil || info.Email != "" {
		t.Fatal(info, e)
	}
	rotated, e := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, tokens.RefreshToken, nil)
	if e != nil || d.Contains(rotated.Scopes, "email") {
		t.Fatal(e)
	}
	f.seed[1].Enabled = true
	if e = f.repo.SeedCatalog(ctx, f.seed); e != nil {
		t.Fatal(e)
	}
	if info, e = f.service.UserInfo(ctx, rotated.AccessToken); e != nil || info.Email != "" {
		t.Fatal("narrow token expanded", e)
	}
	restored, e := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, rotated.RefreshToken, nil)
	if e != nil || !d.Contains(restored.Scopes, "email") {
		t.Fatal("historical consent not restored", e)
	}
	narrowed, e := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, restored.RefreshToken, []string{"openid", "offline_access"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, narrowed.RefreshToken, []string{"openid", "email", "offline_access"}); !errors.Is(e, d.ErrScope) {
		t.Fatal(e)
	}
	code := f.code(t, []string{"openid"}, "public-client")
	bad, e := f.service.Exchange(ctx, d.ClientProof{ClientID: "public-client"}, code, f.app.runtime.Redirects[0], "wrong")
	if e != d.ErrGrant || bad.AccessToken != "" {
		t.Fatal(e)
	}
	good, e := f.service.Exchange(ctx, d.ClientProof{ClientID: "public-client"}, code, f.app.runtime.Redirects[0], f.verifier)
	if e != nil {
		t.Fatal("invalid proof consumed code", e)
	}
	if _, e = f.service.Exchange(ctx, d.ClientProof{ClientID: "public-client"}, code, f.app.runtime.Redirects[0], "wrong"); e != d.ErrGrant {
		t.Fatal(e)
	}
	if _, e = f.service.UserInfo(ctx, good.AccessToken); e != nil {
		t.Fatal("wrong proof revoked family", e)
	}
	if _, e = f.service.Exchange(ctx, d.ClientProof{ClientID: "public-client"}, code, f.app.runtime.Redirects[0], f.verifier); e != d.ErrGrant {
		t.Fatal(e)
	}
	if _, e = f.service.UserInfo(ctx, good.AccessToken); e != d.ErrToken {
		t.Fatal("access-only family survived replay", e)
	}
	// A late failure rolls back grants, codes and audit together.
	before, _ := f.auth.r.database.Collection("auth_oauth_audit").CountDocuments(ctx, bson.M{})
	err := f.repo.Transaction(ctx, func(tx p.Tx) error {
		if e := tx.Audit(d.Audit{ID: "rollback"}); e != nil {
			return e
		}
		return d.ErrConflict
	})
	if err != d.ErrConflict {
		t.Fatal(err)
	}
	after, _ := f.auth.r.database.Collection("auth_oauth_audit").CountDocuments(ctx, bson.M{})
	if before != after {
		t.Fatal("partial audit commit")
	}
}
func TestOAuthMongoUserInfoProfileProjection(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	profileScopes := []d.Scope{
		{Name: "profile.basic.name", Label: "Name", Description: "Read name", Kind: "USERINFO_PROFILE", ProfileField: "basic.name", ProfileValueType: "STRING", Enabled: true},
		{Name: "profile.education.year", Label: "Year", Description: "Read year", Kind: "USERINFO_PROFILE", ProfileField: "education.year", ProfileValueType: "INTEGER", Enabled: true},
		{Name: "profile.preferences.public", Label: "Public", Description: "Read preference", Kind: "USERINFO_PROFILE", ProfileField: "preferences.public", ProfileValueType: "BOOLEAN", Enabled: true},
		{Name: "profile.personal.birthday", Label: "Birthday", Description: "Read birthday", Kind: "USERINFO_PROFILE", ProfileField: "personal.birthday", ProfileValueType: "DATE", Enabled: true},
	}
	f.seed = append(f.seed, profileScopes...)
	if err := f.repo.SeedCatalog(ctx, f.seed); err != nil {
		t.Fatal(err)
	}
	f.app.mu.Lock()
	for _, scope := range profileScopes {
		f.app.runtime.Optional = append(f.app.runtime.Optional, scope.Name)
	}
	f.app.mu.Unlock()
	entries := bson.A{
		bson.M{"key": "basic.name", "valueType": "STRING", "value": "Alice"},
		bson.M{"key": "education.year", "valueType": "INTEGER", "value": int32(2024)},
		bson.M{"key": "personal.birthday", "valueType": "DATE", "value": "2000-02-29"},
		bson.M{"key": "preferences.public", "valueType": "BOOLEAN", "value": false},
	}
	if _, err := f.repo.db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": f.auth.c.AuthID}, bson.M{"$set": bson.M{"profile.entries": entries, "profile.revision": int64(2), "profile.updatedAt": time.Now()}}); err != nil {
		t.Fatal(err)
	}
	scopes := []string{"openid"}
	for _, scope := range profileScopes {
		scopes = append(scopes, scope.Name)
	}
	tokens := f.tokens(t, scopes...)
	info, err := f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || len(info.Profile) != 4 {
		t.Fatalf("profile = %#v, %v", info.Profile, err)
	}
	if info.Profile[0].Key != "basic.name" || info.Profile[0].Value.Text != "Alice" || info.Profile[1].Value.Integer != 2024 || info.Profile[2].Value.Text != "2000-02-29" || info.Profile[3].Value.Boolean {
		t.Fatalf("typed projection = %#v", info.Profile)
	}
	if _, err = f.repo.db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": f.auth.c.AuthID}, bson.M{"$set": bson.M{"profile.entries.0.value": "Alice 2", "profile.revision": int64(3), "profile.updatedAt": time.Now()}}); err != nil {
		t.Fatal(err)
	}
	info, err = f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || info.Profile[0].Value.Text != "Alice 2" {
		t.Fatal("current value not projected", err)
	}
	for index := range f.seed {
		if f.seed[index].Kind == "USERINFO_PROFILE" {
			f.seed[index].Enabled = false
		}
	}
	if err = f.repo.SeedCatalog(ctx, f.seed); err != nil {
		t.Fatal(err)
	}
	duplicate := bson.A{bson.M{"key": "basic.name", "valueType": "STRING", "value": "a"}, bson.M{"key": "basic.name", "valueType": "STRING", "value": "b"}}
	if _, err = f.repo.db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": f.auth.c.AuthID}, bson.M{"$set": bson.M{"profile.entries": duplicate, "profile.revision": int64(4), "profile.updatedAt": time.Now()}}); err != nil {
		t.Fatal(err)
	}
	info, err = f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || len(info.Profile) != 0 {
		t.Fatal("disabled profile scope read profile", err)
	}
	for index := range f.seed {
		if f.seed[index].Name == "profile.basic.name" {
			f.seed[index].Enabled = true
		}
	}
	if err = f.repo.SeedCatalog(ctx, f.seed); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.UserInfo(ctx, tokens.AccessToken); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("corrupt profile did not fail closed", err)
	}
}
func TestOAuthMongoConcurrentCodeAndRefresh(t *testing.T) {
	f := newOAuthFixture(t)
	code := f.code(t, []string{"openid", "offline_access"}, "public-client")
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := []d.TokenResponse{}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := f.service.Exchange(t.Context(), d.ClientProof{ClientID: "public-client"}, code, f.app.runtime.Redirects[0], f.verifier)
			if e == nil {
				mu.Lock()
				success = append(success, out)
				mu.Unlock()
			} else if e != d.ErrGrant {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if len(success) != 1 {
		t.Fatal("code successes", len(success))
	}
	if _, e := f.service.UserInfo(t.Context(), success[0].AccessToken); e != d.ErrToken {
		t.Fatal("replay family active", e)
	}
	token := f.tokens(t, "openid", "offline_access")
	success = nil
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := f.service.Refresh(t.Context(), d.ClientProof{ClientID: "public-client"}, token.RefreshToken, nil)
			if e == nil {
				mu.Lock()
				success = append(success, out)
				mu.Unlock()
			} else if e != d.ErrGrant {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if len(success) != 1 {
		t.Fatal("refresh successes", len(success))
	}
	// No cleartext token, code or ID token persisted in any OAuth collection.
	for _, kind := range []string{"codes", "access", "refresh", "families", "audit"} {
		cur, e := f.auth.r.database.Collection("auth_oauth_"+kind).Find(t.Context(), bson.M{})
		if e != nil {
			t.Fatal(e)
		}
		var docs []bson.M
		if e = cur.All(t.Context(), &docs); e != nil {
			t.Fatal(e)
		}
		data, _ := json.Marshal(docs)
		for _, secret := range []string{code, token.AccessToken, token.RefreshToken, token.IDToken} {
			if secret != "" && containsBytes(data, []byte(secret)) {
				t.Fatal("plaintext persisted", kind)
			}
		}
	}
}
func containsBytes(a, b []byte) bool {
	for i := 0; i+len(b) <= len(a); i++ {
		if string(a[i:i+len(b)]) == string(b) {
			return true
		}
	}
	return false
}

func TestOAuthMongoRuntimeChangesAndAccountIndependence(t *testing.T) {
	f := newOAuthFixture(t)
	ctx := t.Context()
	first := f.tokens(t, "openid", "email", "offline_access")
	oldCode := f.code(t, []string{"openid", "email"}, "public-client")
	f.app.mu.Lock()
	f.app.runtime.VersionID = "version-two"
	f.app.runtime.PublicationRevision++
	f.app.runtime.Optional = []string{"offline_access"}
	f.app.mu.Unlock()
	if _, e := f.service.Exchange(ctx, d.ClientProof{ClientID: "public-client"}, oldCode, f.app.runtime.Redirects[0], f.verifier); e != d.ErrGrant {
		t.Fatal("old tuple exchanged", e)
	}
	info, e := f.service.UserInfo(ctx, first.AccessToken)
	if e != nil || info.Email != "" {
		t.Fatal("current version did not reduce disclosure", e)
	}
	// Historical consent survives, but platform logout does not revoke a family.
	_, e = f.auth.r.database.Collection(SessionCollection).UpdateMany(ctx, bson.M{"authId": f.auth.c.AuthID}, bson.M{"$set": bson.M{"revokedAt": time.Now()}})
	if e != nil {
		t.Fatal(e)
	}
	refreshed, e := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, first.RefreshToken, nil)
	if e != nil || d.Contains(refreshed.Scopes, "email") {
		t.Fatal("background refresh", e)
	}
	f.app.mu.Lock()
	f.app.runtime.Optional = []string{"offline_access", "email"}
	f.app.mu.Unlock()
	refreshed, e = f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, refreshed.RefreshToken, nil)
	if e != nil || !d.Contains(refreshed.Scopes, "email") {
		t.Fatal("major/version history lost", e)
	}
	f.session = f.auth.login(t).SessionToken
	secretCode := f.code(t, []string{"openid", "email"}, "secret-client")
	confidential, e := f.service.Exchange(ctx, d.ClientProof{ClientID: "secret-client", Secret: "secret", Basic: true}, secretCode, f.app.runtime.Redirects[0], f.verifier)
	if e != nil {
		t.Fatal(e)
	}
	other, e := f.service.UserInfo(ctx, confidential.AccessToken)
	if e != nil || other.Subject != info.Subject {
		t.Fatal("same app client pairwise mismatch", e)
	}
	// Public client cannot revoke a confidential client's access token.
	if e = f.service.RevokeToken(ctx, d.ClientProof{ClientID: "public-client"}, confidential.AccessToken, ""); e != nil {
		t.Fatal(e)
	}
	if _, e = f.service.UserInfo(ctx, confidential.AccessToken); e != nil {
		t.Fatal("cross-client revocation", e)
	}
	f.app.mu.Lock()
	f.app.fail = d.ErrUnavailable
	f.app.mu.Unlock()
	if _, e = f.service.UserInfo(ctx, confidential.AccessToken); e != d.ErrUnavailable {
		t.Fatal("dependency became token rejection", e)
	}
	grants, e := f.service.ListGrants(ctx, f.session, "", 50)
	if e != nil || len(grants) != 1 {
		t.Fatal(e)
	}
	if _, e = f.service.RevokeGrant(ctx, f.session, grants[0].ID, grants[0].Revision, true, nil); e != nil {
		t.Fatal("offline App blocked revoke", e)
	}
}
func TestOAuthMongoUnknownCommitReturnsNoCredential(t *testing.T) {
	f := newOAuthFixture(t)
	code := f.code(t, []string{"openid"}, "public-client")
	faulty, name := sessionRevocationFaultRepository(t, f.auth.r.database)
	repository := NewOAuthRepository(faulty, faulty.database)
	service, e := uc.New(repository, f.app, f.crypto, uc.Config{Issuer: "https://auth.example.test/oidc", SectorSuffix: "sectors.example.test"})
	if e != nil {
		t.Fatal(e)
	}
	admin := f.auth.r.database.Client().Database("admin")
	if e = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": name, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		_ = admin.RunCommand(context.Background(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	out, e := service.Exchange(ctx, d.ClientProof{ClientID: "public-client"}, code, f.app.runtime.Redirects[0], f.verifier)
	if e != d.ErrUnavailable || out.AccessToken != "" || out.IDToken != "" {
		t.Fatal("unknown commit exposed tokens", e)
	}
}
