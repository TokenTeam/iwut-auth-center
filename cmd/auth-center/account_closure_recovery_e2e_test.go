package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	decisionpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_owner_exit"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	closure "iwut-auth-center/internal/accountclosure/domain"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/oauthcrypto"
	"iwut-auth-center/internal/adapter/ownerexitclient"
	owner "iwut-auth-center/internal/ownerexit/domain"
	owneruc "iwut-auth-center/internal/ownerexit/usecase"
)

// A pre-termination Mongo backup can lack the shared decision entirely or retain
// PENDING without the receipt, even though an independent termination ledger and
// the actual App provider already know the exit. No local fake provider is used.
func TestAccountClosureRecoveryActualApp(t *testing.T) {
	f := newOwnerExitWireFixture(t)
	auth, e := ma.NewAuthenticationRepository(f.DB, 8, 5)
	if e != nil {
		t.Fatal(e)
	}
	repo, e := ma.NewAccountClosureRepository(auth)
	if e != nil {
		t.Fatal(e)
	}
	if e = ma.EnsureAccountClosureSchema(t.Context(), f.DB); e != nil {
		t.Fatal(e)
	}
	owners := ma.NewOwnerExitRepository(auth)
	app := ownerexitclient.New(f.AppConn, oauthcrypto.Key{ID: "auth-service", Private: f.ServiceKey})
	for _, mode := range []string{"missing", "pending_without_receipt"} {
		t.Run(mode, func(t *testing.T) {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			association := make([]byte, 32)
			_, _ = rand.Read(association)
			user, _ := registerUser(t, f.Conn, key, association)
			now := time.Now().UTC().Truncate(time.Millisecond)
			op := owner.Operation{OperationID: uuid.NewString(), AuthID: user.AuthId, Purpose: owner.Closure, Decision: owner.Pending, AccountRevision: 1, DeveloperRevision: 0, PermissionRevision: 1, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), NextAttemptAt: now.Add(4 * time.Minute)}
			if e := auth.WithAuthTransaction(t.Context(), func(tx context.Context) error { _, e := auth.CreateOwnerExitTx(tx, op); return e }); e != nil {
				t.Fatal(e)
			}
			prepared, e := app.Prepare(t.Context(), op)
			if e != nil || prepared.ReceiptID == "" {
				t.Fatal(prepared, e)
			}
			if mode == "missing" {
				if _, e = f.DB.Collection(ma.OwnerExitCollection).DeleteOne(t.Context(), bson.M{"operationId": op.OperationID}); e != nil {
					t.Fatal(e)
				}
			}
			terminal := closure.Termination{AuthID: user.AuthId, OperationID: op.OperationID, AccountRevision: 2, TerminatedAt: now}
			if e = repo.Replay(t.Context(), terminal); e != nil {
				t.Fatal(e)
			}
			// A second startup replay is idempotent while the remote receipt is unknown.
			if e = repo.Replay(t.Context(), terminal); e != nil {
				t.Fatal("repeat replay", e)
			}
			if mode == "pending_without_receipt" {
				if _, e = owners.Get(t.Context(), user.AuthId, op.OperationID); !errors.Is(e, owner.ErrUnavailable) {
					t.Fatal("quarantined decision exposed", e)
				}
				if _, e = owners.Due(t.Context(), now.Add(time.Hour), 100); e != nil {
					t.Fatal(e)
				}
				var raw bson.M
				if e = f.DB.Collection(ma.OwnerExitCollection).FindOne(t.Context(), bson.M{"operationId": op.OperationID}).Decode(&raw); e != nil || raw["decision"] != owner.Pending || raw["recoveryReceiptRequired"] != true {
					t.Fatal("worker guessed cancellation", raw, e)
				}
				caller := serviceCallContext(t, t.Context(), f.ServiceKey, "app-center", "app-center-2026-01", "iwut-auth-center")
				if _, e = decisionpb.NewAccountOwnerExitDecisionServiceClient(f.Conn).GetAccountOwnerExitDecision(caller, &decisionpb.GetAccountOwnerExitDecisionRequest{AuthId: user.AuthId, OperationId: op.OperationID}); status.Code(e) != codes.Unavailable {
					t.Fatal("callback leaked uncertain decision", e)
				}
			}
			observed, e := app.Status(t.Context(), owner.Operation{AuthID: user.AuthId, OperationID: op.OperationID, Purpose: owner.Closure})
			if e != nil || observed.Decision != owner.Pending || observed.ReceiptID != prepared.ReceiptID {
				t.Fatal("actual App recovery query", observed, e)
			}
			if e = repo.RecoverOwner(t.Context(), terminal, observed); e != nil {
				t.Fatal(e)
			}
			decided, e := owners.Get(t.Context(), user.AuthId, op.OperationID)
			if e != nil || decided.Decision != owner.Committed || decided.ReceiptID != prepared.ReceiptID {
				t.Fatal(decided, e)
			}
			if e = owneruc.New(owners, app).Tick(t.Context()); e != nil {
				t.Fatal(e)
			}
			remote, e := app.Status(t.Context(), decided)
			if e != nil || remote.Decision != owner.Committed {
				t.Fatal(remote, e)
			}
		})
	}
}
