package mongo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/closereauthsigner"
	d "iwut-auth-center/internal/applicationclosereauth/domain"
	uc "iwut-auth-center/internal/applicationclosereauth/usecase"
	pp "iwut-auth-center/internal/password/port"
	pu "iwut-auth-center/internal/password/usecase"
)

func appClosePasswordFixture(t *testing.T) (passwordFixture, *uc.Service, []byte, string, d.Challenge, []byte) {
	t.Helper()
	f := attachPassword(t, newAuthenticationFixture(t))
	if err := EnsureApplicationCloseReauthSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	repo, err := NewApplicationCloseReauthRepository(f.r)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := pu.NewReauth(f.repository, f.engine, f.quota)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := closereauthsigner.New("gate-test", key)
	if err != nil {
		t.Fatal(err)
	}
	service, err := uc.New(repo, f.p, signer, "test-issuer", verifier)
	if err != nil {
		t.Fatal(err)
	}
	session := f.login(t)
	digest, _ := f.p.TokenDigest(session.SessionToken)
	app := uuid.NewString()
	challenge, err := service.Begin(t.Context(), digest, app)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := uc.SigningPayload(challenge.OperationID, app, challenge.Challenge)
	return f, service, digest, app, challenge, signCloseReauth(t, f.key, payload)
}

func TestApplicationCloseReauthMongoPasswordRequiredAndSharedFailureBudget(t *testing.T) {
	f, service, digest, app, challenge, signature := appClosePasswordFixture(t)
	if _, err := service.Complete(t.Context(), digest, challenge.OperationID, app, signature, "", "127.0.0.1"); !errors.Is(err, d.ErrInvalid) {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		sig, password := signature, "wrong current password"
		if i%2 == 1 {
			changed := append([]byte(nil), challenge.Challenge...)
			changed[0] ^= 1
			payload, _ := uc.SigningPayload(challenge.OperationID, app, changed)
			sig, password = signCloseReauth(t, f.key, payload), initialPassword
		}
		if _, err := service.Complete(t.Context(), digest, challenge.OperationID, app, sig, password, "127.0.0.1"); !errors.Is(err, d.ErrFailed) {
			t.Fatalf("failure %d = %v", i, err)
		}
	}
	if _, err := service.Complete(t.Context(), digest, challenge.OperationID, app, signature, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrFailed) {
		t.Fatal("five failures allowed proof", err)
	}
	var doc closeReauthDocument
	if err := f.r.database.Collection(ApplicationCloseReauthOperationCollection).FindOne(t.Context(), bson.M{"operationid": challenge.OperationID}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.FailedAttempts != 5 || doc.State != d.Pending || doc.JTI != "" {
		t.Fatalf("bad failure state: %#v", doc)
	}
}

func TestApplicationCloseReauthMongoReplayRequiresCurrentPassword(t *testing.T) {
	f, service, digest, app, challenge, signature := appClosePasswordFixture(t)
	first, err := service.Complete(t.Context(), digest, challenge.OperationID, app, signature, initialPassword, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Complete(t.Context(), digest, challenge.OperationID, app, signature, "wrong current password", "127.0.0.1"); !errors.Is(err, d.ErrFailed) {
		t.Fatal("password-free replay", err)
	}
	again, err := service.Complete(t.Context(), digest, challenge.OperationID, app, signature, initialPassword, "127.0.0.1")
	if err != nil || first != again {
		t.Fatal("replay drift", err)
	}
	// Revision drift alone also closes the final replay path, without trusting an
	// unchanged account or credential generation to imply password authority.
	if _, err = f.r.database.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"passwordRevision": int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Complete(t.Context(), digest, challenge.OperationID, app, signature, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrFailed) {
		t.Fatal("stale password revision replay", err)
	}
}

type changeAfterVerification struct {
	pp.PasswordVerifier
	after func()
}

func (v changeAfterVerification) VerifyPassword(ctx context.Context, in pp.ReauthRequest) (int64, error) {
	rev, err := v.PasswordVerifier.VerifyPassword(ctx, in)
	if err == nil {
		v.after()
	}
	return rev, err
}

func TestApplicationCloseReauthMongoFinalFenceRejectsPasswordChangeAfterVerification(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(strconv.FormatBool(completed), func(t *testing.T) {
			f, original, digest, app, challenge, signature := appClosePasswordFixture(t)
			wantState, wantJTI := d.Pending, ""
			if completed {
				if _, err := original.Complete(t.Context(), digest, challenge.OperationID, app, signature, initialPassword, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
				var doc closeReauthDocument
				if err := f.r.database.Collection(ApplicationCloseReauthOperationCollection).FindOne(t.Context(), bson.M{"operationid": challenge.OperationID}).Decode(&doc); err != nil {
					t.Fatal(err)
				}
				wantState, wantJTI = d.Completed, doc.JTI
			}
			verifier, _ := pu.NewReauth(f.repository, f.engine, f.quota)
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			signer, _ := closereauthsigner.New("gate-test", key)
			repo, _ := NewApplicationCloseReauthRepository(f.r)
			service, err := uc.New(repo, f.p, signer, "issuer", changeAfterVerification{verifier, func() {
				if _, e := f.r.database.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"passwordRevision": int64(1)}}); e != nil {
					t.Fatal(e)
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = service.Complete(t.Context(), digest, challenge.OperationID, app, signature, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrFailed) {
				t.Fatal("stale attestation committed", err)
			}
			var doc closeReauthDocument
			if err = f.r.database.Collection(ApplicationCloseReauthOperationCollection).FindOne(t.Context(), bson.M{"operationid": challenge.OperationID}).Decode(&doc); err != nil {
				t.Fatal(err)
			}
			if doc.State != wantState || doc.JTI != wantJTI {
				t.Fatal("proof state changed after password drift")
			}
		})
	}
}

func TestApplicationCloseReauthMongoRejectsMalformedPasswordRevision(t *testing.T) {
	for i, value := range []any{nil, int32(1), float64(1), "1", int64(0)} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			f, service, digest, app, challenge, signature := appClosePasswordFixture(t)
			if _, err := f.r.database.Collection(ApplicationCloseReauthOperationCollection).UpdateOne(t.Context(), bson.M{"operationid": challenge.OperationID}, bson.M{"$set": bson.M{"passwordrevision": value}}, options.UpdateOne().SetBypassDocumentValidation(true)); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Complete(t.Context(), digest, challenge.OperationID, app, signature, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrInconsistent) {
				t.Fatal("malformed revision accepted", err)
			}
		})
	}
}
