package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	mongo "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/reviewer/domain"
	"os"
	"strconv"
	"strings"
	"time"
)

// Bootstrap is a separate composition: database only, never service listeners or
// identity keys. A durable marker prevents restart or rerun from restoring grants.
func bootstrapPlatformAdmin(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("bootstrap-platform-admin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("auth-id", "", "existing active USER auth ID")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !domain.ValidID(*id) {
		return errors.New("usage: auth-center bootstrap-platform-admin --auth-id <existing-user-auth-id>")
	}
	env := func(key, def string) string {
		if value, ok := os.LookupEnv(key); ok {
			return strings.TrimSpace(value)
		}
		return def
	}
	client, err := mongo.NewClient(env(config.MongoURIEnv, config.DefaultMongoURI))
	if err != nil {
		return errors.New("bootstrap Mongo connection unavailable")
	}
	defer client.Disconnect(context.Background())
	db, err := mongo.NewDatabase(client, env(config.MongoDatabaseEnv, config.DefaultMongoDatabase))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = mongo.EnsureAuthenticationSchema(ctx, db); err != nil {
		return err
	}
	if err = mongo.EnsurePrincipalSchema(ctx, db); err != nil {
		return err
	}
	if err = mongo.EnsurePlatformAdministratorSchema(ctx, db); err != nil {
		return err
	}
	if err = mongo.EnsureReviewerSchema(ctx, db); err != nil {
		return err
	}
	auth, err := mongo.NewAuthenticationRepository(db, 1, 1)
	if err != nil {
		return err
	}
	ready, err := strconv.ParseBool(env("AUTH_EMAIL_RECOVERY_READY", "false"))
	if err != nil {
		return errors.New("invalid AUTH_EMAIL_RECOVERY_READY")
	}
	login, err := strconv.ParseBool(env("AUTH_EMAIL_LOGIN_ENABLED", "false"))
	if err != nil {
		return errors.New("invalid AUTH_EMAIL_LOGIN_ENABLED")
	}
	repo, err := mongo.NewPlatformAdministratorRepository(auth, ready && login)
	if err != nil {
		return err
	}
	result, err := repo.Bootstrap(ctx, *id)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		AuthID  string `json:"authId"`
		Applied bool   `json:"applied"`
		EventID string `json:"eventId"`
	}{*id, result.Applied, result.EventID})
}
