package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/google/uuid"
	m "go.mongodb.org/mongo-driver/v2/mongo"
	"google.golang.org/grpc"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/testutil/smtpcapture"
	"os"
	"path/filepath"
	"testing"
)

type passwordWireFixture struct {
	env     map[string]string
	conn    *grpc.ClientConn
	db      *m.Database
	capture *smtpcapture.Server
	stop    func()
}

func newPasswordWireFixture(t *testing.T, flags map[string]string) *passwordWireFixture {
	t.Helper()
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	_, callers := testServiceCallerRegistry(t)
	issuer, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&issuer.PublicKey)
	dir := t.TempDir()
	keyFile, catalog := filepath.Join(dir, "key.pem"), filepath.Join(dir, "catalog.json")
	for path, data := range map[string][]byte{keyFile: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), catalog: []byte(`{"definitions":[]}`)} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keys, _ := json.Marshal(map[string]string{"test": keyFile})
	dbName := "password_wire_" + uuid.NewString()
	env := map[string]string{config.UserEndpointsEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t), "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_PROFILE_CATALOG_FILE": catalog, "AUTH_USER_IDENTITY_ISSUER": "password-test", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keys), "AUTH_PASSWORD_MANAGEMENT_ENABLED": "true", "AUTH_EMAIL_LOGIN_ENABLED": "true", "AUTH_EMAIL_LOGIN_CODE_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	for k, v := range flags {
		env[k] = v
	}
	capture := enableEmailRegistrationFixture(t, env)
	c, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	client, err := ma.NewClient(uri)
	if err != nil {
		t.Fatal(err)
	}
	db := client.Database(dbName)
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = client.Disconnect(context.Background()) })
	app, cleanup, err := wireApp(c)
	if err != nil {
		t.Fatal(err)
	}
	conn, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	t.Cleanup(stop)
	return &passwordWireFixture{env, conn, db, capture, stop}
}
