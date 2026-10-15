package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/passwordcrypto"
	ap "iwut-auth-center/internal/authentication/port"
	oauth "iwut-auth-center/internal/oauth/domain"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
	uc "iwut-auth-center/internal/password/usecase"
	"sync"
	"testing"
	"time"
)

type resetMail struct {
	code  string
	calls int
	fail  bool
}

func (s *resetMail) Send(_ context.Context, _ string, purpose, code string, _ time.Time) error {
	if purpose != "RESET_PASSWORD" {
		return errors.New("wrong purpose")
	}
	s.calls++
	s.code = code
	if s.fail {
		return errors.New("SMTP failure")
	}
	return nil
}

type resetFixture struct {
	passwordFixture
	repo     *PasswordResetRepository
	reset    *uc.ResetService
	mail     *resetMail
	protocol *passwordcrypto.Protocol
	clock    time.Time
}

func newResetFixture(t *testing.T) *resetFixture {
	t.Helper()
	f := attachPassword(t, newAuthenticationFixture(t))
	return buildResetFixture(t, f)
}
func buildResetFixture(t *testing.T, f passwordFixture) *resetFixture {
	t.Helper()
	if err := EnsurePasswordResetSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	protocol, _ := passwordcrypto.NewProtocol(bytes32(11), "iwut-auth-center:test")
	repo, err := NewPasswordResetRepository(f.repository, protocol, EmailLimits{5, 5, 20, 10000})
	if err != nil {
		t.Fatal(err)
	}
	mail := &resetMail{}
	budget, _ := passwordcrypto.NewAddressBudget(bytes32(19))
	service, err := uc.NewResetService(repo, protocol, f.p, f.engine, f.quota, mail, "iwut-auth-center:test", budget)
	if err != nil {
		t.Fatal(err)
	}
	out := &resetFixture{f, repo, service, mail, protocol, time.Now().UTC().Truncate(time.Millisecond)}
	f.r.clock = func() time.Time { return out.clock }
	service.SetClock(func() time.Time { return out.clock })
	return out
}
func (f *resetFixture) beginReset(t *testing.T) p.Reset {
	t.Helper()
	o, err := f.reset.Begin(t.Context(), uuid.NewString(), "primary@example.test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func TestPasswordResetRetiresAllKeysAndRecoversOnlySameCompletedInput(t *testing.T) {
	f := newResetFixture(t)
	session := f.login(t)
	other := secondaryCredential(t, f.authenticationFixture, f.c.AuthID)
	o := f.beginReset(t)
	code := f.mail.code
	if err := f.reset.Complete(t.Context(), o.OperationID, code, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrUnchanged) {
		t.Fatal(err)
	}
	if err := f.reset.Complete(t.Context(), o.OperationID, code, "short", "127.0.0.1"); !errors.Is(err, d.ErrPolicy) {
		t.Fatal(err)
	}
	if _, err := f.u.Check(t.Context(), session.SessionToken); err != nil {
		t.Fatal("failed reset revoked Session", err)
	}
	if err := f.reset.Complete(t.Context(), o.OperationID, code, changedPassword, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.u.Check(t.Context(), session.SessionToken); !errors.Is(err, ap.ErrSessionInvalid) {
		t.Fatal("old Session survived", err)
	}
	for _, key := range []string{f.c.CredentialID, other.c.CredentialID} {
		var c CredentialDocument
		if err := f.r.database.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": key}).Decode(&c); err != nil {
			t.Fatal(err)
		}
		if c.RevokedAt != nil || c.CredentialRevision != 1 {
			t.Fatal("unbounded key rewrite instead of cutoff")
		}
		if err := f.r.WithAuthTransaction(t.Context(), func(tx context.Context) error { return f.r.ConfirmPrincipalCredentialTx(tx, f.c.AuthID, key, f.clock) }); !errors.Is(err, ap.ErrAuthenticationFailed) {
			t.Fatal("retired key revived", err)
		}
	}
	f.clock = f.clock.Add(11 * time.Minute)
	if err := f.reset.Complete(t.Context(), o.OperationID, code, changedPassword, "127.0.0.1"); err != nil {
		t.Fatal("completed result not recoverable", err)
	}
	if err := f.reset.Complete(t.Context(), o.OperationID, code, "different new password", "127.0.0.1"); !errors.Is(err, d.ErrReset) {
		t.Fatal(err)
	}
	var principal bson.M
	_ = f.r.database.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": f.c.AuthID}).Decode(&principal)
	if principal["accountRevision"] != int64(2) || principal["minimumCredentialRevision"] != int64(2) {
		t.Fatal(principal)
	}
	for _, col := range []string{PasswordAuditCollection, PasswordNotificationCollection} {
		n, _ := f.r.database.Collection(col).CountDocuments(t.Context(), bson.M{})
		if n != 1 {
			t.Fatal("duplicate side effect", col, n)
		}
	}
}
func TestPasswordResetFiveFailuresIdempotencyAndReplacement(t *testing.T) {
	f := newResetFixture(t)
	request := uuid.NewString()
	o, err := f.reset.Begin(t.Context(), request, "primary@example.test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.reset.Begin(t.Context(), request, "primary@example.test", "127.0.0.1")
	if err != nil || again.OperationID != o.OperationID || f.mail.calls != 1 {
		t.Fatal(again, err)
	}
	if _, err = f.reset.Begin(t.Context(), uuid.NewString(), "primary@example.test", "127.0.0.1"); !errors.Is(err, d.ErrLimited) {
		t.Fatal("mail cooldown bypass", err)
	}
	wrong := "00000000"
	if wrong == f.mail.code {
		wrong = "11111111"
	}
	valid := f.mail.code
	for i := 0; i < 5; i++ {
		if err = f.reset.Complete(t.Context(), o.OperationID, wrong, changedPassword, "127.0.0.1"); !errors.Is(err, d.ErrReset) {
			t.Fatal(i, err)
		}
	}
	if err = f.reset.Complete(t.Context(), o.OperationID, valid, changedPassword, "127.0.0.1"); !errors.Is(err, d.ErrReset) {
		t.Fatal("exhausted accepted", err)
	}
	f.clock = f.clock.Add(time.Minute)
	next := f.beginReset(t)
	f.clock = next.ExpiresAt
	if err = f.reset.Complete(t.Context(), next.OperationID, f.mail.code, changedPassword, "127.0.0.1"); !errors.Is(err, d.ErrReset) {
		t.Fatal("expiry accepted", err)
	}
}
func TestPasswordResetRoleAndAccountVersionChangesInvalidatePendingAndCompleted(t *testing.T) {
	for _, completed := range []bool{false, true} {
		for _, kind := range []string{"role", "account"} {
			t.Run(kind+map[bool]string{false: "/pending", true: "/completed"}[completed], func(t *testing.T) {
				f := newResetFixture(t)
				o := f.beginReset(t)
				code := f.mail.code
				if completed {
					if err := f.reset.Complete(t.Context(), o.OperationID, code, changedPassword, "127.0.0.1"); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "role" {
					_, _ = f.r.database.Collection(EmailDirectoryCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"revision": int64(1), "loginRoleRevision": int64(1)}})
				} else {
					accountTransition(t, f.r, f.c.AuthID, "DISABLED")
					accountTransition(t, f.r, f.c.AuthID, "ACTIVE")
				}
				if err := f.reset.Complete(t.Context(), o.OperationID, code, changedPassword, "127.0.0.1"); !errors.Is(err, d.ErrReset) {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestPasswordResetPlaceholderAndColdKeyCannotBecomeAuthority(t *testing.T) {
	f := newResetFixture(t)
	o, err := f.reset.Begin(t.Context(), uuid.NewString(), "unknown@example.test", "127.0.0.1")
	if err != nil || o.Acceptable || f.mail.calls != 0 {
		t.Fatal(o, err)
	}
	if err = f.reset.Complete(t.Context(), o.OperationID, "12345678", changedPassword, "127.0.0.1"); !errors.Is(err, d.ErrReset) {
		t.Fatal(err)
	}
	actual := f.beginReset(t)
	code := f.mail.code
	protocol, _ := passwordcrypto.NewProtocol(bytes32(22), "iwut-auth-center:test")
	passwords, _ := NewPasswordRepository(f.r, protocol.KeyID())
	repo, _ := NewPasswordResetRepository(passwords, protocol, EmailLimits{5, 5, 20, 10000})
	if _, err = repo.ReadReset(t.Context(), actual.OperationID, f.clock); !errors.Is(err, d.ErrReset) {
		t.Fatal("cold key consumed old operation", err)
	}
	if err = f.reset.Complete(t.Context(), actual.OperationID, code, changedPassword, "127.0.0.1"); err != nil {
		t.Fatal("key switch damaged long-term password", err)
	}
}
func TestPasswordResetConcurrentCompleteHasOneAudit(t *testing.T) {
	f := newResetFixture(t)
	o := f.beginReset(t)
	code := f.mail.code
	var wg sync.WaitGroup
	out := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out <- f.reset.Complete(t.Context(), o.OperationID, code, changedPassword, "127.0.0.1")
		}()
	}
	wg.Wait()
	close(out)
	for err := range out {
		if err != nil {
			t.Fatal(err)
		}
	}
	n, _ := f.r.database.Collection(PasswordAuditCollection).CountDocuments(t.Context(), bson.M{"action": "PASSWORD_RESET"})
	if n != 1 {
		t.Fatal(n)
	}
}

func TestPasswordResetClosureCleanupKeepsOtherOwners(t *testing.T) {
	f := newClosureFixture(t)
	if err := EnsurePasswordResetSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	protocol, _ := passwordcrypto.NewProtocol(bytes32(11), "iwut-auth-center:test")
	passwords, _ := NewPasswordRepository(f.r, protocol.KeyID())
	repo, _ := NewPasswordResetRepository(passwords, protocol, EmailLimits{5, 5, 20, 10000})
	now := f.clock
	o, _, err := repo.BeginReset(t.Context(), p.Reset{OperationID: uuid.NewString(), RequestID: uuid.NewString(), Email: "primary@example.test", AuthID: uuid.NewString(), ServiceID: "iwut-auth-center:test", KeyID: protocol.KeyID(), Status: "PENDING", AccountRevision: 1, PasswordRevision: 1, RoleRevision: 1, RequestMAC: bytes32(1), CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), ResendAfter: now.Add(time.Minute), RetainUntil: now.Add(24 * time.Hour)}, "12345678", "127.0.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	closureInsert(t, f, PasswordResetCollection, bson.M{"operationId": uuid.NewString(), "authId": "other-owner"})
	ready := f.ready(t)
	f.close(t, ready)
	f.acknowledge(t, ready.OperationID)
	f.drain(t)
	if closureCount(t, f, PasswordResetCollection, bson.M{"operationId": o.OperationID}) != 0 || closureCount(t, f, PasswordResetCollection, bson.M{"authId": "other-owner"}) != 1 {
		t.Fatal("reset cleanup isolation failed")
	}
}

func TestPasswordResetInvalidatesOAuthButPreservesConsentAndSubject(t *testing.T) {
	for _, client := range []string{"public-client", "secret-client"} {
		t.Run(client, func(t *testing.T) {
			oauthFixture := newOAuthFixture(t)
			f := buildResetFixture(t, attachPassword(t, oauthFixture.auth))
			proof := oauth.ClientProof{ClientID: client}
			if client == "secret-client" {
				proof.Basic = true
				proof.Secret = "secret"
			}
			code := oauthFixture.code(t, []string{"openid", "email", "offline_access"}, client)
			tokens, err := oauthFixture.service.Exchange(t.Context(), proof, code, oauthFixture.app.runtime.Redirects[0], oauthFixture.verifier)
			if err != nil {
				t.Fatal(err)
			}
			pending := oauthFixture.code(t, []string{"openid", "email", "offline_access"}, client)
			before := map[string]bson.Raw{}
			for _, col := range []string{"auth_oauth_grants", "auth_oauth_subjects"} {
				raw, err := f.r.database.Collection(col).FindOne(t.Context(), bson.M{}).Raw()
				if err != nil {
					t.Fatal(err)
				}
				before[col] = raw
			}
			var address string
			if err = f.r.WithAuthTransaction(t.Context(), func(tx context.Context) error {
				binding, _, err := ReadPrimaryEmailTx(tx, f.r.database, f.c.AuthID)
				address = binding.Email
				return err
			}); err != nil {
				t.Fatal(err)
			}
			o, err := f.reset.Begin(t.Context(), uuid.NewString(), address, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if err = f.reset.Complete(t.Context(), o.OperationID, f.mail.code, changedPassword, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			if _, err = oauthFixture.service.UserInfo(t.Context(), tokens.AccessToken); !errors.Is(err, oauth.ErrToken) {
				t.Fatal("reset retained access", err)
			}
			if _, err = oauthFixture.service.Refresh(t.Context(), proof, tokens.RefreshToken, nil); !errors.Is(err, oauth.ErrGrant) {
				t.Fatal("reset retained refresh", err)
			}
			if _, err = oauthFixture.service.Exchange(t.Context(), proof, pending, oauthFixture.app.runtime.Redirects[0], oauthFixture.verifier); !errors.Is(err, oauth.ErrGrant) {
				t.Fatal("reset retained code", err)
			}
			for col, raw := range before {
				after, err := f.r.database.Collection(col).FindOne(t.Context(), bson.M{}).Raw()
				if err != nil || string(raw) != string(after) {
					t.Fatal("reset changed consent/sub", col, err)
				}
			}
		})
	}
}
