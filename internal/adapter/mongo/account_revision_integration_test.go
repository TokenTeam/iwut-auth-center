package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	account "iwut-auth-center/internal/account/domain"
	ap "iwut-auth-center/internal/authentication/port"
	emaildomain "iwut-auth-center/internal/emailaccount/domain"
	loginDomain "iwut-auth-center/internal/emaillogin/domain"
	oauth "iwut-auth-center/internal/oauth/domain"
	profile "iwut-auth-center/internal/profile/domain"
	"testing"
	"time"
)

// Writes through the same serialized status transition used by governance; fixture
// transitions isolate authentication proof validity from administrator enrollment.
func accountTransition(t *testing.T, r *AuthenticationRepository, id, status string) {
	t.Helper()
	if err := r.WithAuthTransaction(t.Context(), func(tx context.Context) error {
		_, err := r.database.Collection(PrincipalCollection).UpdateOne(tx, bson.M{"authId": id}, bson.M{"$set": bson.M{"accountStatus": status}, "$inc": bson.M{"accountRevision": int64(1)}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
func TestAccountRevisionDeviceProofAndSessionsNeverRevive(t *testing.T) {
	f := newAuthenticationFixture(t)
	old := f.login(t)
	pending := f.begin(t)
	accountTransition(t, f.r, f.c.AuthID, "DISABLED")
	placeholder := f.begin(t)
	accountTransition(t, f.r, f.c.AuthID, "ACTIVE")
	for _, c := range []struct {
		id      string
		payload []byte
	}{{pending.OperationID, pending.SigningPayload}, {placeholder.OperationID, placeholder.SigningPayload}} {
		if _, err := f.u.Complete(t.Context(), c.id, signAuthentication(t, f.key, c.payload)); !errors.Is(err, ap.ErrAuthenticationFailed) {
			t.Fatalf("old proof revived: %v", err)
		}
	}
	if _, err := f.u.Check(t.Context(), old.SessionToken); !errors.Is(err, ap.ErrSessionInvalid) {
		t.Fatalf("old session revived: %v", err)
	}
	fresh := f.login(t)
	ss, err := f.u.Check(t.Context(), fresh.SessionToken)
	if err != nil || ss.AccountRevision != 3 || fresh.AuthID != old.AuthID {
		t.Fatal(ss, err)
	}
	count, err := f.r.database.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{"authId": old.AuthID, "revokedAt": nil})
	if err != nil || count != 2 {
		t.Fatal("state transition scanned/revoked historical sessions", count, err)
	}
}
func TestAccountRevisionLRUIgnoresOldGenerations(t *testing.T) {
	f := newAuthenticationFixture(t)
	old := f.login(t)
	accountTransition(t, f.r, f.c.AuthID, "DISABLED")
	accountTransition(t, f.r, f.c.AuthID, "ACTIVE")
	for range 10 {
		f.login(t)
	}
	var s SessionDocument
	if err := f.r.database.Collection(SessionCollection).FindOne(t.Context(), bson.M{"sessionId": old.SessionID}).Decode(&s); err != nil || s.RevokedAt != nil {
		t.Fatal("old generation consumed current capacity", s, err)
	}
}
func TestAccountRevisionOAuthCredentialsNeverRevive(t *testing.T) {
	for _, client := range []string{"public-client", "secret-client"} {
		t.Run(client, func(t *testing.T) {
			f := newOAuthFixture(t)
			scopes := []string{"openid", "email", "offline_access"}
			proof := oauth.ClientProof{ClientID: client}
			verifier := f.verifier
			if client == "secret-client" {
				proof.Basic = true
				proof.Secret = "secret"
			}
			code := f.code(t, scopes, client)
			tokens, err := f.service.Exchange(t.Context(), proof, code, f.app.runtime.Redirects[0], verifier)
			if err != nil {
				t.Fatal(err)
			}
			pendingCode := f.code(t, scopes, client)
			pending := f.begin(t, scopes, client, 1)
			before, err := f.service.UserInfo(t.Context(), tokens.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			accountTransition(t, f.auth.r, f.auth.c.AuthID, "DISABLED")
			accountTransition(t, f.auth.r, f.auth.c.AuthID, "ACTIVE")
			if _, err = f.service.UserInfo(t.Context(), tokens.AccessToken); !errors.Is(err, oauth.ErrToken) {
				t.Fatal("access revived", err)
			}
			if _, err = f.service.Refresh(t.Context(), proof, tokens.RefreshToken, nil); !errors.Is(err, oauth.ErrGrant) {
				t.Fatal("refresh revived", err)
			}
			if _, err = f.service.Exchange(t.Context(), proof, pendingCode, f.app.runtime.Redirects[0], verifier); !errors.Is(err, oauth.ErrGrant) {
				t.Fatal("code revived", err)
			}
			f.session = f.auth.login(t).SessionToken
			if _, err = f.service.Confirm(t.Context(), pending.InteractionID, pending.CSRF, pending.PresentationID, f.session, scopes, true); err == nil {
				t.Fatal("old consent revived")
			}
			freshCode := f.code(t, scopes, client)
			fresh, err := f.service.Exchange(t.Context(), proof, freshCode, f.app.runtime.Redirects[0], verifier)
			if err != nil {
				t.Fatal(err)
			}
			after, err := f.service.UserInfo(t.Context(), fresh.AccessToken)
			if err != nil || before.Subject != after.Subject {
				t.Fatal("pairwise subject changed", before, after, err)
			}
		})
	}
}
func TestAccountRevisionProfileCASRejectsRestoredJWS(t *testing.T) {
	f := newAuthenticationFixture(t)
	_, err := f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"profile": bson.M{"entries": bson.A{}, "revision": int64(1), "updatedAt": time.Now()}}})
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := NewProfileRepository(f.r.database)
	old := account.WithIdentity(t.Context(), f.c.AuthID, 1)
	if _, err = repo.Read(old, f.c.AuthID); err != nil {
		t.Fatal(err)
	}
	accountTransition(t, f.r, f.c.AuthID, "DISABLED")
	accountTransition(t, f.r, f.c.AuthID, "ACTIVE")
	if err = repo.Commit(old, f.c.AuthID, 1, profile.Snapshot{Revision: 2, UpdatedAt: time.Now()}); !errors.Is(err, profile.ErrIdentity) {
		t.Fatal("old JWS write revived", err)
	}
	if _, err = repo.Read(account.WithIdentity(t.Context(), f.c.AuthID, 3), f.c.AuthID); err != nil {
		t.Fatal(err)
	}
}

func TestAccountRevisionEmailLoginAndBindingNeverRevive(t *testing.T) {
	f := newEmailLoginFixture(t)
	clearMailCooldown(t, f)
	key := newSigningKey(t)
	oldLogin, err := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	// These proposals exercise account-generation races, not the separately
	// verified shared owner mail cooldown across LOGIN and ADD.
	clearMailCooldown(t, f)
	pendingBind, err := f.accounts.Begin(t.Context(), f.owner.SessionToken, emaildomain.Begin{RequestID: uuid.NewString(), Email: "new@example.test", ExpectedDirectoryRevision: 1, Source: "127.0.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	accountTransition(t, f.repo.AuthenticationRepository, f.owner.AuthID, "DISABLED")
	clearMailCooldown(t, f)
	placeholder, err := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	accountTransition(t, f.repo.AuthenticationRepository, f.owner.AuthID, "ACTIVE")
	for _, c := range []loginDomain.Challenge{oldLogin, placeholder} {
		if _, err = f.login.Complete(t.Context(), c.OperationID, "00005678", loginSignature(t, key, c), "127.0.0.1"); !errors.Is(err, loginDomain.ErrFailed) {
			t.Fatal("email proof revived", err)
		}
	}
	clearMailCooldown(t, f)
	freshChallenge, err := f.login.Begin(t.Context(), loginBegin(key, "login@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := f.login.Complete(t.Context(), freshChallenge.OperationID, "00005678", loginSignature(t, key, freshChallenge), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	freshDigest, _ := f.protocol.TokenDigest(fresh.SessionToken)
	if _, err = f.accounts.Complete(t.Context(), fresh.SessionToken, pendingBind.Operation.OperationID, "00001234", "", nil, false, "127.0.0.1"); !errors.Is(err, emaildomain.ErrSession) {
		t.Fatal("old email binding revived with fresh Session", err)
	}
	ss, err := f.repo.CheckSession(t.Context(), freshDigest, time.Now())
	if err != nil || ss.AccountRevision != 3 {
		t.Fatal(ss, err)
	}
}
