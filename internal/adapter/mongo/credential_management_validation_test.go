package mongo

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	"testing"
	"time"
)

func TestCredentialManagementCredentialMetadataShapes(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	raw, err := f.r.database.Collection(CredentialCollection).FindOne(t.Context(), bson.M{"credentialId": target.c.CredentialID}).Raw()
	if err != nil {
		t.Fatal(err)
	}
	var doc bson.M
	if bson.Unmarshal(raw, &doc) != nil {
		t.Fatal("decode")
	}
	for _, tc := range []struct {
		name   string
		change func(bson.M)
		valid  bool
	}{
		{"both absent", func(v bson.M) { delete(v, "label"); delete(v, "labelRevision") }, true},
		{"missing label", func(v bson.M) { delete(v, "label") }, false},
		{"missing revision", func(v bson.M) { delete(v, "labelRevision") }, false},
		{"int32", func(v bson.M) { v["labelRevision"] = int32(0) }, false},
		{"negative", func(v bson.M) { v["labelRevision"] = int64(-1) }, false},
		{"null", func(v bson.M) { v["label"] = nil }, false},
		{"noncanonical", func(v bson.M) { v["label"] = " name " }, false},
		{"format character", func(v bson.M) { v["label"] = "name\u200d" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := bson.M{}
			for k, v := range doc {
				copy[k] = v
			}
			tc.change(copy)
			encoded, err := bson.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			var c CredentialDocument
			err = bson.Unmarshal(encoded, &c)
			if (err == nil) != tc.valid {
				t.Fatal(err)
			}
		})
	}
}
func TestCredentialManagementForeignAndUnknownTargetsAreIndistinguishable(t *testing.T) {
	f := newCredentialFixture(t)
	other := secondaryCredential(t, f.authenticationFixture, "other-owner")
	for _, id := range []string{other.c.CredentialID, uuid.NewString()} {
		if _, err := f.service.List(t.Context(), f.digest, 10, id); !errors.Is(err, d.ErrCursor) {
			t.Fatal(err)
		}
		if _, err := f.service.SetLabel(t.Context(), f.digest, id, "name", 0); !errors.Is(err, d.ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := f.service.Begin(t.Context(), f.digest, uuid.NewString(), id); !errors.Is(err, d.ErrNotFound) {
			t.Fatal(err)
		}
	}
}
func TestCredentialManagementCompletedReplayStillRequiresCurrentAuthority(t *testing.T) {
	for _, mode := range []string{"session-revoked", "key-revoked", "disabled", "restored", "closed"} {
		t.Run(mode, func(t *testing.T) {
			f := newCredentialFixture(t)
			target := f.target(t)
			op := f.begin(t, target.c.CredentialID)
			sig := signAuthentication(t, f.key, op.SigningPayload)
			if err := f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, sig, initialPassword, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "session-revoked":
				_, _ = f.r.database.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": f.session.SessionID}, bson.M{"$set": bson.M{"revokedAt": f.clock}})
			case "key-revoked":
				_, _ = f.r.database.Collection(CredentialCollection).UpdateOne(t.Context(), bson.M{"credentialId": f.c.CredentialID}, bson.M{"$set": bson.M{"revokedAt": f.clock}})
			case "disabled":
				accountTransition(t, f.r, f.c.AuthID, "DISABLED")
			case "restored":
				accountTransition(t, f.r, f.c.AuthID, "DISABLED")
				accountTransition(t, f.r, f.c.AuthID, "ACTIVE")
			case "closed":
				_, _ = f.r.database.Collection(PrincipalCollection).ReplaceOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"authId": f.c.AuthID, "principalType": "USER", "accountStatus": "CLOSED", "accountRevision": int64(2), "terminatedAt": f.clock, "closureOperationId": uuid.NewString()})
			}
			if err := f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, sig, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrSession) {
				t.Fatal("historical result resurrected authority", err)
			}
		})
	}
}
func TestCredentialManagementPendingExpiryAndStrictOperationVersion(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	op := f.begin(t, target.c.CredentialID)
	sig := signAuthentication(t, f.key, op.SigningPayload)
	_, err := f.r.database.Collection(CredentialManagementOperationCollection).UpdateOne(t.Context(), bson.M{"operationId": op.Operation.OperationID}, bson.M{"$set": bson.M{"completedAt": nil}})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, sig, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("coerced completion state", err)
	}
	_, _ = f.r.database.Collection(CredentialManagementOperationCollection).UpdateOne(t.Context(), bson.M{"operationId": op.Operation.OperationID}, bson.M{"$unset": bson.M{"completedAt": ""}})
	_, err = f.r.database.Collection(CredentialManagementOperationCollection).UpdateOne(t.Context(), bson.M{"operationId": op.Operation.OperationID}, bson.M{"$set": bson.M{"passwordRevision": int32(1)}})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, sig, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("coerced password revision", err)
	}
	_, _ = f.r.database.Collection(CredentialManagementOperationCollection).UpdateOne(t.Context(), bson.M{"operationId": op.Operation.OperationID}, bson.M{"$set": bson.M{"passwordRevision": int64(1)}})
	f.clock = op.Operation.ExpiresAt
	if err = f.service.Complete(t.Context(), f.digest, op.Operation.OperationID, sig, initialPassword, "127.0.0.1"); !errors.Is(err, d.ErrProof) {
		t.Fatal("expired pending executed", err)
	}
}
func TestCredentialManagementUnknownCommitDoesNotClaimSuccess(t *testing.T) {
	f := newCredentialFixture(t)
	target := f.target(t)
	fault, appName := sessionRevocationFaultRepository(t, f.r.database)
	repo, _ := NewCredentialManagementRepository(fault, "iwut-auth-center:test")
	admin := f.r.database.Client().Database("admin")
	if err := admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	disable := func() {
		_ = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	}
	t.Cleanup(disable)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if _, err := repo.SetLabel(ctx, f.digest, target.c.CredentialID, "name", 0, uuid.NewString(), f.clock); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("unknown commit claimed result", err)
	}
	disable() // actual result can be read without blindly overriding another writer
	if _, err := f.service.List(t.Context(), f.digest, 50, ""); err != nil {
		t.Fatal(err)
	}
}
