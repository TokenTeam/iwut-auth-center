package mongo

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	d "iwut-auth-center/internal/oauth/domain"
)

func stringsContainsDecodedIDToken(token, fragment string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	return err == nil && strings.Contains(string(payload), fragment)
}

func oauthCampusFixture(t *testing.T) *oauthFixture {
	t.Helper()
	f := newOAuthFixture(t)
	if err := EnsureCampusSchema(t.Context(), f.repo.db); err != nil {
		t.Fatal(err)
	}
	f.seed = append(f.seed, d.Scope{Name: "campus.whut", Label: "Campus member", Description: "Read current verified campus membership, not student status", Kind: "USERINFO_CAMPUS", Enabled: true})
	if err := f.repo.SeedCatalog(t.Context(), f.seed); err != nil {
		t.Fatal(err)
	}
	f.app.runtime.Optional = append(f.app.runtime.Optional, "campus.whut")
	return f
}

func insertOAuthCampusFact(t *testing.T, f *oauthFixture) {
	t.Helper()
	id := uuid.NewString()
	if _, err := f.repo.db.Collection(EmailBindingCollection).InsertOne(t.Context(), emailBindingDocument{BindingID: id, AuthID: f.auth.c.AuthID, Email: "member@whut.edu.cn", VerifiedAt: time.Now().UTC().Truncate(time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.db.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": f.auth.c.AuthID}, bson.M{"$inc": bson.M{"revision": int64(1), "verifiedCount": int64(1)}}); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthMongoCampusProjectionCatalogAndRefresh(t *testing.T) {
	f := oauthCampusFixture(t)
	ctx := t.Context()
	tokens := f.tokens(t, "openid", "campus.whut", "offline_access")
	info, err := f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || info.Campus != nil || info.Subject == "" {
		t.Fatalf("uncertified response: %#v %v", info, err)
	}
	subject := info.Subject
	insertOAuthCampusFact(t, f)
	info, err = f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || info.Campus == nil || info.Campus.Institution != "WHUT" || info.Subject != subject || info.Email != "" || len(info.Profile) != 0 {
		t.Fatalf("certified response: %#v %v", info, err)
	}
	// Campus scope adds no raw identity/certification fields to the ID Token.
	for _, fragment := range []string{"iwut_campus", "certifiedAt", f.auth.c.AuthID} {
		if stringsContainsDecodedIDToken(tokens.IDToken, fragment) {
			t.Fatal("ID Token leaked campus data", fragment)
		}
	}
	for index := range f.seed {
		if f.seed[index].Name == "campus.whut" {
			f.seed[index].Enabled = false
		}
	}
	if err = f.repo.SeedCatalog(ctx, f.seed); err != nil {
		t.Fatal(err)
	}
	info, err = f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || info.Campus != nil || info.Subject != subject {
		t.Fatalf("disabled scope: %#v %v", info, err)
	}
	narrowed, err := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, tokens.RefreshToken, nil)
	if err != nil || d.Contains(narrowed.Scopes, "campus.whut") {
		t.Fatalf("disabled refresh: %#v %v", narrowed, err)
	}
	for index := range f.seed {
		if f.seed[index].Name == "campus.whut" {
			f.seed[index].Enabled = true
		}
	}
	if err = f.repo.SeedCatalog(ctx, f.seed); err != nil {
		t.Fatal(err)
	}
	info, err = f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || info.Campus == nil || info.Subject != subject {
		t.Fatalf("restored original token: %#v %v", info, err)
	}
	info, err = f.service.UserInfo(ctx, narrowed.AccessToken)
	if err != nil || info.Campus != nil {
		t.Fatalf("narrow access token expanded: %#v %v", info, err)
	}
	restored, err := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, narrowed.RefreshToken, nil)
	if err != nil || !d.Contains(restored.Scopes, "campus.whut") {
		t.Fatalf("restored family ceiling: %#v %v", restored, err)
	}
	info, err = f.service.UserInfo(ctx, restored.AccessToken)
	if err != nil || info.Campus == nil || info.Subject != subject {
		t.Fatalf("restored refresh response: %#v %v", info, err)
	}
	f.app.runtime.Optional = []string{"offline_access"}
	info, err = f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || info.Campus != nil {
		t.Fatalf("undeclared scope: %#v %v", info, err)
	}
	f.app.runtime.Optional = append(f.app.runtime.Optional, "campus.whut")
	info, err = f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || info.Campus == nil {
		t.Fatalf("restored version: %#v %v", info, err)
	}
	grants, err := f.service.ListGrants(ctx, f.session, "", 50)
	if err != nil || len(grants) != 1 || !d.Contains(grants[0].Scopes, "campus.whut") {
		t.Fatal("current filtering changed durable consent", grants, err)
	}
	if _, err = f.service.RevokeGrant(ctx, f.session, grants[0].ID, grants[0].Revision, false, []string{"campus.whut"}); err != nil {
		t.Fatal(err)
	}
	if info, err = f.service.UserInfo(ctx, tokens.AccessToken); !errors.Is(err, d.ErrToken) || info.Campus != nil {
		t.Fatal("revoked campus grant accepted", info, err)
	}
}

func TestOAuthMongoCampusDirectoryCorruptionFailsEntireDisclosure(t *testing.T) {
	f := oauthCampusFixture(t)
	ctx := t.Context()
	insertOAuthCampusFact(t, f)
	campus := f.tokens(t, "openid", "campus.whut")
	openid := f.tokens(t, "openid")
	for _, corruption := range []bson.M{{"$unset": bson.M{"verifiedAt": ""}}, {"$set": bson.M{"verifiedAt": "malformed"}}, {"$set": bson.M{"email": "Member@whut.edu.cn"}}} {
		if _, err := f.repo.db.Collection(EmailBindingCollection).UpdateOne(ctx, bson.M{"authId": f.auth.c.AuthID, "email": bson.M{"$regex": "(?i)^member@"}}, bson.M{"$set": bson.M{"email": "member@whut.edu.cn", "verifiedAt": time.Now().UTC().Truncate(time.Millisecond)}}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.db.Collection(EmailBindingCollection).UpdateOne(ctx, bson.M{"authId": f.auth.c.AuthID, "email": "member@whut.edu.cn"}, corruption, options.UpdateOne().SetBypassDocumentValidation(true)); err != nil {
			t.Fatal(err)
		}
		for _, token := range []string{campus.AccessToken, openid.AccessToken} {
			if info, err := f.service.UserInfo(ctx, token); !errors.Is(err, d.ErrUnavailable) || info.Subject != "" || info.Campus != nil {
				t.Fatal("bad directory returned partial disclosure", info, err)
			}
		}
	}
}
func TestOAuthMongoCampusLastBasisRemovalKeepsGrantAndSubject(t *testing.T) {
	f := oauthCampusFixture(t)
	ctx := t.Context()
	insertOAuthCampusFact(t, f)
	tokens := f.tokens(t, "openid", "campus.whut", "offline_access")
	before, err := f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || before.Campus == nil {
		t.Fatal(before, err)
	}
	// Deliberately seed a historical fact: it must have no authority now.
	if _, err = f.repo.db.Collection(CampusCertificationCollection).InsertOne(ctx, bson.M{"authId": f.auth.c.AuthID, "institution": "WHUT", "certifiedAt": time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err = f.auth.r.WithAuthTransaction(ctx, func(tx context.Context) error {
		if _, err := f.repo.db.Collection(EmailBindingCollection).DeleteOne(tx, bson.M{"authId": f.auth.c.AuthID, "email": "member@whut.edu.cn"}); err != nil {
			return err
		}
		_, err := f.repo.db.Collection(EmailDirectoryCollection).UpdateOne(tx, bson.M{"authId": f.auth.c.AuthID}, bson.M{"$inc": bson.M{"revision": int64(1), "verifiedCount": int64(-1)}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	after, err := f.service.UserInfo(ctx, tokens.AccessToken)
	if err != nil || after.Campus != nil || after.Subject != before.Subject {
		t.Fatal(after, err)
	}
	refreshed, err := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, tokens.RefreshToken, nil)
	if err != nil || !d.Contains(refreshed.Scopes, "campus.whut") {
		t.Fatal("removal implicitly revoked consent", refreshed, err)
	}
	info, err := f.service.UserInfo(ctx, refreshed.AccessToken)
	if err != nil || info.Campus != nil || info.Subject != before.Subject {
		t.Fatal(info, err)
	}
}

func TestOAuthMongoCampusLifecycleGates(t *testing.T) {
	for _, gate := range []string{"application closed", "account disabled", "account closed"} {
		t.Run(gate, func(t *testing.T) {
			f := oauthCampusFixture(t)
			ctx := t.Context()
			insertOAuthCampusFact(t, f)
			tokens := f.tokens(t, "openid", "campus.whut", "offline_access")
			if gate == "application closed" {
				if err := EnsureApplicationClosureSchema(ctx, f.repo.db); err != nil {
					t.Fatal(err)
				}
				repo, _ := NewApplicationClosureRepository(f.auth.r)
				now := time.Now().UTC().Truncate(time.Millisecond)
				if _, err := repo.Apply(ctx, "app-one", uuid.NewString(), now, uuid.NewString(), "app-center", now); err != nil {
					t.Fatal(err)
				}
			} else {
				status := "DISABLED"
				if gate == "account closed" {
					status = "CLOSED"
				}
				if _, err := f.repo.db.Collection(PrincipalCollection).UpdateOne(ctx, bson.M{"authId": f.auth.c.AuthID}, bson.M{"$set": bson.M{"accountStatus": status}, "$inc": bson.M{"accountRevision": int64(1)}}); err != nil {
					t.Fatal(err)
				}
			}
			if info, err := f.service.UserInfo(ctx, tokens.AccessToken); !errors.Is(err, d.ErrToken) || info.Campus != nil {
				t.Fatalf("%s leaked campus: %#v %v", gate, info, err)
			}
			if _, err := f.service.Refresh(ctx, d.ClientProof{ClientID: "public-client"}, tokens.RefreshToken, nil); !errors.Is(err, d.ErrGrant) {
				t.Fatalf("%s renewed campus token: %v", gate, err)
			}
		})
	}
}

func TestOAuthMongoCampusCatalogRejectsChangedMeaning(t *testing.T) {
	f := oauthCampusFixture(t)
	ctx := t.Context()
	for name, mutate := range map[string]func(*d.Scope){
		"resource":          func(s *d.Scope) { s.Kind = "RESOURCE"; s.Audience = "auth" },
		"arbitrary campus":  func(s *d.Scope) { s.Name = "campus.other" },
		"profile metadata":  func(s *d.Scope) { s.ProfileField = "education.campus_areas" },
		"value metadata":    func(s *d.Scope) { s.ProfileValueType = "BOOLEAN" },
		"resource audience": func(s *d.Scope) { s.Audience = "auth" },
	} {
		t.Run(name, func(t *testing.T) {
			seed := append([]d.Scope(nil), f.seed...)
			mutate(&seed[len(seed)-1])
			if err := f.repo.SeedCatalog(ctx, seed); !errors.Is(err, d.ErrScope) {
				t.Fatalf("changed campus meaning accepted: %v", err)
			}
		})
	}
	discovery, err := f.service.Discovery(ctx)
	if err != nil || !d.Contains(discovery["scopes_supported"].([]string), "campus.whut") {
		t.Fatal("invalid seeding changed valid catalog", discovery, err)
	}
	// Storage corruption is not a disabled/not-yet-requested scope: the entire
	// Catalog dependency fails closed rather than silently dropping a bad entry.
	if _, err = f.repo.db.Collection("auth_oauth_catalog").UpdateOne(ctx, bson.M{"_id": "current"}, bson.M{"$set": bson.M{"data.scopes.0.audience": "resource"}}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Discovery(ctx); !errors.Is(err, d.ErrUnavailable) {
		t.Fatalf("corrupt campus catalog accepted: %v", err)
	}
}
