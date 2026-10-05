package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	closure "iwut-auth-center/internal/accountclosure/usecase"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/adapter/terminationledger"
	"iwut-auth-center/internal/config"
)

// Offline recovery deliberately has no App client, signing keys or listeners.
// The normal runtime completes local/App cleanup after this termination gate.
func reconcileAccountClosures(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: auth-center reconcile-account-closures")
	}
	ledger, err := terminationledger.Open(os.Getenv("AUTH_TERMINATION_LEDGER_DIR"))
	if err != nil {
		return err
	}
	env := func(key, fallback string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		return fallback
	}
	client, err := ma.NewClient(env(config.MongoURIEnv, config.DefaultMongoURI))
	if err != nil {
		return errors.New("closure reconciliation Mongo connection unavailable")
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Disconnect(ctx)
	}()
	db, err := ma.NewDatabase(client, env(config.MongoDatabaseEnv, config.DefaultMongoDatabase))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err = ma.EnsurePrincipalSchema(ctx, db); err != nil {
		return err
	}
	if err = ma.EnsureAuthenticationSchema(ctx, db); err != nil {
		return err
	}
	if err = ma.EnsureAccountClosureSchema(ctx, db); err != nil {
		return err
	}
	auth, err := ma.NewAuthenticationRepository(db, 1, 1)
	if err != nil {
		return err
	}
	repo, err := ma.NewAccountClosureRepository(auth)
	if err != nil {
		return err
	}
	if err = closure.ReconcileTerminations(ctx, repo, ledger, time.Now().UTC().Truncate(time.Millisecond)); err != nil {
		return errors.New("account closure reconciliation failed; keep service isolated")
	}
	return json.NewEncoder(out).Encode(struct {
		Reconciled     bool `json:"reconciled"`
		CleanupPending bool `json:"cleanupPending"`
	}{true, true})
}
