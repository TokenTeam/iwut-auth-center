package mongo

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/v2/bson"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"iwut-auth-center/internal/adapter/passwordcrypto"
	d "iwut-auth-center/internal/password/domain"
	p "iwut-auth-center/internal/password/port"
	uc "iwut-auth-center/internal/password/usecase"
	"testing"
	"time"
)

type resetRacingEngine struct {
	p.Engine
	after func()
}

func (e resetRacingEngine) Hash(ctx context.Context, s string) (d.Material, error) {
	material, err := e.Engine.Hash(ctx, s)
	if err == nil {
		e.after()
	}
	return material, err
}
func TestPasswordResetFinalVersionAndAuditRollback(t *testing.T) {
	for _, kind := range []string{"version", "audit"} {
		t.Run(kind, func(t *testing.T) {
			f := newResetFixture(t)
			o := f.beginReset(t)
			code := f.mail.code
			if kind == "version" {
				engine := resetRacingEngine{f.engine, func() {
					_, err := f.r.database.Collection(PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": f.c.AuthID}, bson.M{"$inc": bson.M{"passwordRevision": int64(1)}})
					if err != nil {
						t.Fatal(err)
					}
				}}
				budget, _ := passwordcrypto.NewAddressBudget(bytes32(19))
				service, err := uc.NewResetService(f.repo, f.protocol, f.p, engine, f.quota, f.mail, "iwut-auth-center:test", budget)
				if err != nil {
					t.Fatal(err)
				}
				service.SetClock(func() time.Time { return f.clock })
				if err = service.Complete(t.Context(), o.OperationID, code, changedPassword, "127.0.0.1"); !errors.Is(err, d.ErrReset) {
					t.Fatal("stale password snapshot committed", err)
				}
			} else {
				_, err := f.r.database.Collection(PasswordAuditCollection).Indexes().CreateOne(t.Context(), m.IndexModel{Keys: bson.D{{Key: "action", Value: 1}}, Options: options.Index().SetUnique(true)})
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.r.database.Collection(PasswordAuditCollection).InsertOne(t.Context(), bson.M{"operationId": "fixture", "action": "PASSWORD_RESET"})
				if err != nil {
					t.Fatal(err)
				}
				if err = f.reset.Complete(t.Context(), o.OperationID, code, changedPassword, "127.0.0.1"); err == nil {
					t.Fatal("audit failure claimed success")
				}
			}
			var principal bson.M
			_ = f.r.database.Collection(PrincipalCollection).FindOne(t.Context(), bson.M{"authId": f.c.AuthID}).Decode(&principal)
			if principal["accountRevision"] != int64(1) || principal["minimumCredentialRevision"] != int64(1) {
				t.Fatal("partial reset", principal)
			}
			stored, err := f.repo.read(t.Context(), bson.M{"operationId": o.OperationID})
			if err != nil || stored.Status != "PENDING" {
				t.Fatal(stored, err)
			}
			n, _ := f.r.database.Collection(PasswordNotificationCollection).CountDocuments(t.Context(), bson.M{})
			if n != 0 {
				t.Fatal("uncommitted notification", n)
			}
		})
	}
}
func TestPasswordResetUnknownCommitCannotClaimSuccess(t *testing.T) {
	f := newResetFixture(t)
	o := f.beginReset(t)
	snapshot, err := f.repo.ReadReset(t.Context(), o.OperationID, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	next, err := f.engine.Hash(t.Context(), changedPassword)
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := f.protocol.ResetCompletionMAC(o.OperationID, o.CodeMAC, changedPassword)
	fault, appName := sessionRevocationFaultRepository(t, f.r.database)
	passwords, _ := NewPasswordRepository(fault, f.protocol.KeyID())
	repo, _ := NewPasswordResetRepository(passwords, f.protocol, EmailLimits{5, 5, 20, 10000})
	admin := f.r.database.Client().Database("admin")
	if err = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "alwaysOn"}, {Key: "data", Value: bson.M{"appName": appName, "failCommands": bson.A{"commitTransaction"}, "errorCode": 50, "errorLabels": bson.A{"UnknownTransactionCommitResult"}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.RunCommand(t.Context(), bson.D{{Key: "configureFailPoint", Value: "failCommand"}, {Key: "mode", Value: "off"}}).Err()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err = repo.CompleteReset(ctx, snapshot, next, tag, f.clock); err == nil {
		t.Fatal("unknown commit claimed success")
	}
}
func TestPasswordResetRejectsMalformedVersionAndDeployment(t *testing.T) {
	f := newResetFixture(t)
	o := f.beginReset(t)
	_, err := f.r.database.Collection(PasswordResetCollection).UpdateOne(t.Context(), bson.M{"operationId": o.OperationID}, bson.M{"$set": bson.M{"roleRevision": int32(1)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.repo.ReadReset(t.Context(), o.OperationID, f.clock); !errors.Is(err, d.ErrUnavailable) {
		t.Fatal("coerced role revision", err)
	}
	_, _ = f.r.database.Collection(PasswordResetCollection).UpdateOne(t.Context(), bson.M{"operationId": o.OperationID}, bson.M{"$set": bson.M{"roleRevision": int64(1)}})
	protocol, _ := passwordcrypto.NewProtocol(bytes32(11), "iwut-auth-center:other")
	passwords, _ := NewPasswordRepository(f.r, protocol.KeyID())
	other, _ := NewPasswordResetRepository(passwords, protocol, EmailLimits{5, 5, 20, 10000})
	if _, err = other.ReadReset(t.Context(), o.OperationID, f.clock); !errors.Is(err, d.ErrReset) {
		t.Fatal("deployment proof crossover", err)
	}
}
