package mongo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/passwordcrypto"
	auth "iwut-auth-center/internal/authentication/domain"
	authport "iwut-auth-center/internal/authentication/port"
	oauth "iwut-auth-center/internal/oauth/domain"
	pwd "iwut-auth-center/internal/password/domain"
	"iwut-auth-center/internal/password/port"
	"iwut-auth-center/internal/password/usecase"
)

const initialPassword = "a unique first password"
const changedPassword = "a unique second password"

type passwordFixture struct {
	authenticationFixture
	engine     *passwordcrypto.Engine
	repository *PasswordRepository
	quota      *PasswordQuota
	service    *usecase.ChangeService
}

func passwordEngine(t *testing.T, parameters pwd.Parameters) *passwordcrypto.Engine {
	t.Helper()
	blocked := sha256.Sum256([]byte("a blocked password"))
	list := hex.EncodeToString(blocked[:]) + "\n"
	digest := sha256.Sum256([]byte(list))
	b, err := passwordcrypto.LoadBlocklist(strings.NewReader(list), "test-fixture", "TEST ONLY", hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := passwordcrypto.NewExecutor(4, 32, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	e, err := passwordcrypto.New(parameters, b, executor)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func attachPassword(t *testing.T, a authenticationFixture) passwordFixture {
	t.Helper()
	db := a.r.database
	for _, err := range []error{EnsurePasswordSchema(t.Context(), db), EnsurePasswordQuotaSchema(t.Context(), db), EnsureEmailAccountSchema(t.Context(), db)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	e := passwordEngine(t, pwd.DefaultParameters())
	protocol, err := passwordcrypto.NewProtocol(bytes32(11), "iwut-auth-center:test")
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewPasswordRepository(a.r, protocol.KeyID())
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewPasswordQuota(a.r)
	if err != nil {
		t.Fatal(err)
	}
	s, err := usecase.NewChangeService(r, e, protocol, a.p, q, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	material, err := e.Hash(t.Context(), initialPassword)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err = a.r.WithAuthTransaction(t.Context(), func(tx context.Context) error {
		if err = r.InitializePasswordTx(tx, pwd.Record{AuthID: a.c.AuthID, Revision: 1, Material: material, ChangedAt: now}); err != nil {
			return err
		}
		count, err := db.Collection(EmailBindingCollection).CountDocuments(tx, bson.M{"authId": a.c.AuthID})
		if err != nil {
			return err
		}
		if count > 0 {
			return nil
		}
		bindingID := uuid.NewString()
		if _, err = db.Collection(EmailDirectoryCollection).InsertOne(tx, emailDirectoryDocument{AuthID: a.c.AuthID, LoginBindingID: bindingID, Revision: 1, LoginRoleRevision: 1, VerifiedCount: 1}); err != nil {
			return err
		}
		_, err = db.Collection(EmailBindingCollection).InsertOne(tx, emailBindingDocument{BindingID: bindingID, AuthID: a.c.AuthID, Email: "primary@example.test", VerifiedAt: now})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return passwordFixture{a, e, r, q, s}
}
func bytes32(v byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return b
}

func TestPasswordChangePreservesOnlyCurrentCredentialAndReturnsOneToken(t *testing.T) {
	f := attachPassword(t, newAuthenticationFixture(t))
	ctx := t.Context()
	before := f.login(t)
	digest, _ := f.p.TokenDigest(before.SessionToken)
	other := secondaryCredential(t, f.authenticationFixture, f.c.AuthID).c
	requestID := uuid.NewString()
	op, newSession, err := f.service.Change(ctx, before.SessionToken, requestID, initialPassword, changedPassword, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if op == "" || newSession.SessionID == before.SessionID || newSession.SessionToken == before.SessionToken {
		t.Fatal("did not rotate Session")
	}
	if _, err = f.u.Check(ctx, before.SessionToken); !errors.Is(err, authport.ErrSessionInvalid) {
		t.Fatal("old Session survived", err)
	}
	current, err := f.u.Check(ctx, newSession.SessionToken)
	if err != nil || current.AuthenticationMethod != pwd.PasswordAndSession || current.SourceSessionID != before.SessionID || current.PasswordRevision != 2 || current.AccountRevision != 2 {
		t.Fatal("new provenance invalid", current, err)
	}
	if _, eligible, err := f.r.ResolveCredential(ctx, auth.Locator{Kind: auth.CredentialIDLocator, Value: []byte(other.CredentialID)}); err != nil || eligible {
		t.Fatal("other device survived", err)
	}
	if _, _, err = f.service.Change(ctx, before.SessionToken, requestID, initialPassword, changedPassword, "127.0.0.1"); !errors.Is(err, pwd.ErrSessionInvalid) {
		t.Fatal("returned secret to old Session", err)
	}
	recovered := f.login(t)
	status, found, _, err := f.service.Get(ctx, recovered.SessionToken, requestID, "127.0.0.1")
	if err != nil || !found || status.OperationID != op {
		t.Fatal("lost response not recoverable", err)
	}
	if _, result, err := f.service.Change(ctx, recovered.SessionToken, requestID, initialPassword, changedPassword, "127.0.0.1"); !errors.Is(err, pwd.ErrAlreadyCompleted) || result.SessionToken != "" {
		t.Fatal("returned second token", err)
	}
	if _, _, err = f.service.Change(ctx, recovered.SessionToken, requestID, initialPassword, "different replay password", "127.0.0.1"); !errors.Is(err, pwd.ErrRequestConflict) {
		t.Fatal("different replay accepted", err)
	}
	var record pwd.Record
	if err = f.r.WithAuthTransaction(ctx, func(tx context.Context) error {
		var err error
		record, err = f.repository.readPasswordTx(tx, f.c.AuthID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.engine.Verify(ctx, changedPassword, record.Material); err != nil || !ok || record.Revision != 2 {
		t.Fatal("password not updated")
	}
	var oldDoc SessionDocument
	if err = f.r.database.Collection(SessionCollection).FindOne(ctx, bson.M{"tokenDigest": digest}).Decode(&oldDoc); err != nil || oldDoc.RevokedAt != nil {
		t.Fatal("scanned old Sessions", err)
	}
	for _, col := range []string{PasswordChangeCollection, PasswordAuditCollection, PasswordNotificationCollection} {
		n, err := f.r.database.Collection(col).CountDocuments(ctx, bson.M{"authId": f.c.AuthID})
		if err != nil || n != 1 {
			t.Fatal("nonunique side effect", col, n, err)
		}
	}
	accountTransition(t, f.r, f.c.AuthID, "DISABLED")
	accountTransition(t, f.r, f.c.AuthID, "ACTIVE")
	if _, eligible, err := f.r.ResolveCredential(ctx, auth.Locator{Kind: auth.CredentialIDLocator, Value: []byte(other.CredentialID)}); err != nil || eligible {
		t.Fatal("restore revived retired credential", err)
	}
	_ = f.login(t)
}

func TestPasswordChangeFinalRecheckAndAuditRollback(t *testing.T) {
	for _, kind := range []string{"password_changed", "account_disabled", "pending_exit", "audit_failure"} {
		t.Run(kind, func(t *testing.T) {
			f := attachPassword(t, newAuthenticationFixture(t))
			before := f.login(t)
			digest, _ := f.p.TokenDigest(before.SessionToken)
			snapshot, err := f.repository.ReadSnapshot(t.Context(), digest, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			material, err := f.engine.Hash(t.Context(), changedPassword)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			operationID := uuid.NewString()
			newID := uuid.NewString()
			_, newDigest, _ := f.p.NewSessionToken()
			commit := port.ChangeCommit{Snapshot: snapshot, NewMaterial: material, Operation: port.Change{AuthID: f.c.AuthID, RequestID: uuid.NewString(), OperationID: operationID, SourceSessionID: before.SessionID, RetainedCredentialID: f.c.CredentialID, OriginalAccountRevision: 1, OriginalPasswordRevision: 1, KeyID: f.repository.keyID, RequestMAC: bytes32(1), CreatedAt: now, RetainUntil: now.Add(24 * time.Hour)}, Session: auth.Session{AuthID: f.c.AuthID, SessionID: newID, CredentialID: f.c.CredentialID, AuthenticationMethod: pwd.PasswordAndSession, PasswordRevision: 2, AccountRevision: 2, SourceSessionID: before.SessionID, TokenDigest: newDigest, CreatedAt: now, AuthenticatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}}
			switch kind {
			case "password_changed":
				_, err = f.r.database.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$set": bson.M{"passwordRevision": int64(2)}})
			case "account_disabled":
				accountTransition(t, f.r, f.c.AuthID, "DISABLED")
			case "pending_exit":
				_, err = f.r.database.Collection(OwnerExitCollection).InsertOne(t.Context(), bson.M{"authId": f.c.AuthID, "decision": "PENDING"})
			case "audit_failure":
				_, err = f.r.database.Collection(PasswordAuditCollection).InsertOne(t.Context(), bson.M{"operationId": operationID, "authId": "fixture"})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = f.repository.CommitChange(t.Context(), commit, now); err == nil {
				t.Fatal("stale/failed commit succeeded")
			}
			n, err := f.r.database.Collection(SessionCollection).CountDocuments(t.Context(), bson.M{"sessionId": newID})
			if err != nil || n != 0 {
				t.Fatal("partial Session committed", err)
			}
			var principal bson.M
			_ = f.r.database.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": f.c.AuthID}).Decode(&principal)
			if principal["minimumCredentialRevision"] != int64(1) {
				t.Fatal("partial cutoff committed")
			}
		})
	}
}

func TestPasswordChangeWrongAndUnchangedDoNotMutate(t *testing.T) {
	f := attachPassword(t, newAuthenticationFixture(t))
	before := f.login(t)
	for _, values := range [][2]string{{"an incorrect password", changedPassword}, {initialPassword, initialPassword}} {
		if _, _, err := f.service.Change(t.Context(), before.SessionToken, uuid.NewString(), values[0], values[1], "127.0.0.1"); err == nil {
			t.Fatal("wrong/unchanged accepted")
		}
	}
	if _, err := f.u.Check(t.Context(), before.SessionToken); err != nil {
		t.Fatal("failed change kicked account")
	}
	n, _ := f.r.database.Collection(PasswordAuditCollection).CountDocuments(t.Context(), bson.M{})
	if n != 0 {
		t.Fatal("failed change audited as success")
	}
}

func TestPasswordSharedQuotaIsPersistentAtomicAndBounded(t *testing.T) {
	f := newAuthenticationFixture(t)
	if err := EnsurePasswordQuotaSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	q, _ := NewPasswordQuota(f.r)
	now := time.Now().UTC().Truncate(time.Millisecond)
	f.r.clock = func() time.Time { return now }
	var mu sync.Mutex
	success := 0
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := q.Work(t.Context(), "127.0.0.1", f.c.AuthID, 2, now)
			if err == nil {
				mu.Lock()
				success++
				mu.Unlock()
			} else if !errors.Is(err, pwd.ErrLimited) {
				t.Errorf("unexpected quota failure: %v", err)
			}
		}()
	}
	wg.Wait()
	if success != 5 {
		t.Fatal("owner units exceeded", success)
	}
	q2, _ := NewPasswordQuota(f.r)
	if err := q2.Work(t.Context(), "127.0.0.2", f.c.AuthID, 1, now); !errors.Is(err, pwd.ErrLimited) {
		t.Fatal("restart/source switch bypassed owner quota", err)
	}
	now = now.Add(time.Minute)
	if err := q2.Work(t.Context(), "127.0.0.1", f.c.AuthID, 2, now); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordChangeInvalidatesOAuthWithoutRemovingConsentOrSubject(t *testing.T) {
	for _, client := range []string{"public-client", "secret-client"} {
		t.Run(client, func(t *testing.T) {
			f := newOAuthFixture(t)
			passwords := attachPassword(t, f.auth)
			ctx := t.Context()
			scopes := []string{"openid", "email", "offline_access"}
			proof := oauth.ClientProof{ClientID: client}
			if client == "secret-client" {
				proof.Basic = true
				proof.Secret = "secret"
			}
			code := f.code(t, scopes, client)
			tokens, err := f.service.Exchange(ctx, proof, code, f.app.runtime.Redirects[0], f.verifier)
			if err != nil {
				t.Fatal(err)
			}
			before, err := f.service.UserInfo(ctx, tokens.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			pending := f.code(t, scopes, client)
			grantBefore, err := f.auth.r.database.Collection("auth_oauth_grants").FindOne(ctx, bson.M{}).Raw()
			if err != nil {
				t.Fatal(err)
			}
			_, freshSession, err := passwords.service.Change(ctx, f.session, uuid.NewString(), initialPassword, changedPassword, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.service.UserInfo(ctx, tokens.AccessToken); !errors.Is(err, oauth.ErrToken) {
				t.Fatal("old access token survived", err)
			}
			if _, err = f.service.Refresh(ctx, proof, tokens.RefreshToken, nil); !errors.Is(err, oauth.ErrGrant) {
				t.Fatal("old refresh survived", err)
			}
			if _, err = f.service.Exchange(ctx, proof, pending, f.app.runtime.Redirects[0], f.verifier); !errors.Is(err, oauth.ErrGrant) {
				t.Fatal("old code survived", err)
			}
			grantAfter, err := f.auth.r.database.Collection("auth_oauth_grants").FindOne(ctx, bson.M{}).Raw()
			if err != nil || string(grantBefore) != string(grantAfter) {
				t.Fatal("password change erased or changed consent", err)
			}
			f.session = freshSession.SessionToken
			freshCode := f.code(t, scopes, client)
			fresh, err := f.service.Exchange(ctx, proof, freshCode, f.app.runtime.Redirects[0], f.verifier)
			if err != nil {
				t.Fatal(err)
			}
			after, err := f.service.UserInfo(ctx, fresh.AccessToken)
			if err != nil || before.Subject != after.Subject {
				t.Fatal("stable application subject changed", err)
			}
		})
	}
}
