package mongo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/authentication/port"
	"iwut-auth-center/internal/authentication/usecase"
)

func secondaryCredential(t *testing.T, f authenticationFixture, owner string) authenticationFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := elliptic.Marshal(key.Curve, key.X, key.Y)
	fp, _ := f.p.Fingerprint(pub)
	id, _ := f.p.NewID()
	c := domain.Credential{CredentialID: id, AuthID: owner, ProtocolVersion: domain.ProtocolVersion, PublicKey: pub, Fingerprint: fp, CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	if err := f.r.WithAuthTransaction(t.Context(), func(ctx context.Context) error { return f.r.InsertCredentialTx(ctx, c) }); err != nil {
		t.Fatal(err)
	}
	f.key, f.c = key, c
	return f
}

func TestCredentialRevocationPreservesOwnershipAndFirstTime(t *testing.T) {
	f := newAuthenticationFixture(t)
	second := secondaryCredential(t, f, f.c.AuthID)
	foreign := secondaryCredential(t, f, "other-owner")
	callerToken, targetToken := f.login(t), second.login(t)
	caller, err := f.u.Check(t.Context(), callerToken.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	revoke, _ := usecase.NewCredentialRevocation(f.r)
	unknown, _ := f.p.NewID()
	for _, id := range []string{unknown, foreign.c.CredentialID} {
		if err := revoke.Revoke(t.Context(), caller, id); !errors.Is(err, port.ErrNotFound) {
			t.Fatalf("foreign/unknown: %v", err)
		}
	}
	// The challenge was accepted before revocation but cannot commit afterwards.
	pending := second.begin(t)
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); failures <- revoke.Revoke(t.Context(), caller, second.c.CredentialID) }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first CredentialDocument
	if err := f.r.database.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": second.c.CredentialID}).Decode(&first); err != nil {
		t.Fatal(err)
	}
	if first.RevokedAt == nil {
		t.Fatal("missing first revocation timestamp")
	}
	if err := revoke.Revoke(t.Context(), caller, second.c.CredentialID); err != nil {
		t.Fatal(err)
	}
	var repeated CredentialDocument
	if err := f.r.database.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": second.c.CredentialID}).Decode(&repeated); err != nil {
		t.Fatal(err)
	}
	if repeated.RevokedAt == nil || !first.RevokedAt.Equal(*repeated.RevokedAt) {
		t.Fatal("first timestamp changed")
	}
	if _, err := f.u.Check(t.Context(), targetToken.SessionToken); !errors.Is(err, port.ErrSessionInvalid) {
		t.Fatal("target session survived", err)
	}
	if _, err := f.u.Check(t.Context(), callerToken.SessionToken); err != nil {
		t.Fatal("unrelated session failed", err)
	}
	if _, err := second.u.Complete(t.Context(), pending.OperationID, signAuthentication(t, second.key, pending.SigningPayload)); !errors.Is(err, port.ErrAuthenticationFailed) {
		t.Fatal("pending login survived revocation", err)
	}
	duplicate := credentialDocument(second.c)
	duplicate.CredentialID, _ = f.p.NewID()
	if _, err := f.r.database.Collection(CredentialCollection).InsertOne(t.Context(), duplicate); !drivermongo.IsDuplicateKeyError(err) {
		t.Fatal("fingerprint ownership released", err)
	}
}

func TestCredentialRevocationCurrentLastCredentialAndStaleAuthorization(t *testing.T) {
	for _, mode := range []string{"last-credential", "session-revoked", "disabled", "system", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthenticationFixture(t)
			established := f.login(t)
			caller, err := f.u.Check(t.Context(), established.SessionToken)
			if err != nil {
				t.Fatal(err)
			}
			revoke, _ := usecase.NewCredentialRevocation(f.r)
			switch mode {
			case "session-revoked":
				_, err = f.r.database.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": caller.SessionID}, bson.M{"$set": bson.M{"revokedAt": time.Now()}})
			case "disabled":
				_, err = f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": caller.AuthID}, bson.M{"$set": bson.M{"accountStatus": "DISABLED"}})
			case "system":
				_, err = f.r.database.Collection(PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": caller.AuthID}, bson.M{"$set": bson.M{"principalType": "SYSTEM"}})
			case "expired":
				f.r.clock = func() time.Time { return caller.ExpiresAt }
			}
			if err != nil {
				t.Fatal(err)
			}
			err = revoke.Revoke(t.Context(), caller, f.c.CredentialID)
			if mode != "last-credential" {
				if !errors.Is(err, port.ErrSessionInvalid) {
					t.Fatal("stale auth succeeded", err)
				}
				return
			}
			if err != nil {
				t.Fatal("last credential blocked", err)
			}
			if _, err = f.u.Check(t.Context(), established.SessionToken); !errors.Is(err, port.ErrSessionInvalid) {
				t.Fatal("self revoked session survived", err)
			}
			if err = revoke.Revoke(t.Context(), caller, f.c.CredentialID); !errors.Is(err, port.ErrSessionInvalid) {
				t.Fatal("stale retry succeeded", err)
			}
		})
	}
}

func TestCredentialRevocationConcurrentLoginCannotRemainUsable(t *testing.T) {
	f := newAuthenticationFixture(t)
	second := secondaryCredential(t, f, f.c.AuthID)
	established := f.login(t)
	caller, err := f.u.Check(t.Context(), established.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	revoke, _ := usecase.NewCredentialRevocation(f.r)
	pending := second.begin(t)
	sig := signAuthentication(t, second.key, pending.SigningPayload)
	start := make(chan struct{})
	result := make(chan domain.Established, 1)
	failure := make(chan error, 1)
	go func() {
		<-start
		s, e := second.u.Complete(t.Context(), pending.OperationID, sig)
		result <- s
		failure <- e
	}()
	close(start)
	if err := revoke.Revoke(t.Context(), caller, second.c.CredentialID); err != nil {
		t.Fatal(err)
	}
	logged := <-result
	err = <-failure
	if err == nil {
		if _, err = f.u.Check(t.Context(), logged.SessionToken); !errors.Is(err, port.ErrSessionInvalid) {
			t.Fatal("concurrent session usable after revoke", err)
		}
	} else if !errors.Is(err, port.ErrAuthenticationFailed) {
		t.Fatal(err)
	}
}
