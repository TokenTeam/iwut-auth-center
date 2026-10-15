package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_close_reauth"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	ma "iwut-auth-center/internal/adapter/mongo"
	uc "iwut-auth-center/internal/applicationclosereauth/usecase"
	"iwut-auth-center/internal/config"
)

func TestE2E_ApplicationClosePassword_ProductionWire(t *testing.T) {
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	_, callers := testServiceCallerRegistry(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	dir := t.TempDir()
	keyFile, catalog := filepath.Join(dir, "key.pem"), filepath.Join(dir, "catalog.json")
	for path, data := range map[string][]byte{keyFile: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), catalog: []byte(`{"definitions":[]}`)} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keys, _ := json.Marshal(map[string]string{"reauth-test": keyFile})
	databaseName := "app_close_pwd_wire_" + uuid.NewString()
	env := map[string]string{
		config.UserEndpointsEnabledEnv: "true", config.IdentityIssuanceEnabledEnv: "true",
		config.MongoURIEnv: uri, config.MongoDatabaseEnv: databaseName, config.ServiceCallersEnv: callers,
		config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t),
		"AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h",
		"AUTH_PROFILE_CATALOG_FILE": catalog, "AUTH_USER_IDENTITY_ISSUER": "app-close-test",
		"AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keys), "AUTH_USER_IDENTITY_SIGNING_KID": "reauth-test",
		"AUTH_USER_IDENTITY_PRIVATE_KEY_PEM_B64": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
		"AUTH_APPLICATION_CLOSE_REAUTH_ENABLED":  "true", "AUTH_APPLICATION_CLOSE_REAUTH_ACCOUNT_PER_MINUTE": "100",
	}
	enableEmailRegistrationFixture(t, env)
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	dbClient, err := ma.NewClient(uri)
	if err != nil {
		t.Fatal(err)
	}
	db := dbClient.Database(databaseName)
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = dbClient.Disconnect(context.Background()) })
	app, cleanup, err := wireApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	connection, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop()
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registered, _ := registerUser(t, connection, device, nil)
	ctx := sessionCallContext(t.Context(), registered.Session.SessionToken)
	client := pb.NewApplicationCloseReauthServiceClient(connection)
	applicationID := uuid.NewString()
	challenge, err := client.BeginApplicationCloseReauth(ctx, &pb.BeginApplicationCloseReauthRequest{ApplicationId: applicationID})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := uc.SigningPayload(challenge.OperationId, applicationID, challenge.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	request := &pb.CompleteApplicationCloseReauthRequest{OperationId: challenge.OperationId, ApplicationId: applicationID, SignatureDer: signDevice(t, device, payload)}
	if _, err = client.CompleteApplicationCloseReauth(ctx, request); status.Code(err) != codes.InvalidArgument {
		t.Fatal("omitted password bypass", err)
	}
	request.CurrentPassword = "wrong current password"
	if _, err = client.CompleteApplicationCloseReauth(ctx, request); status.Code(err) != codes.Unauthenticated {
		t.Fatal("wrong password", err)
	}
	request.CurrentPassword = "a long fixture password 123"
	proof, err := client.CompleteApplicationCloseReauth(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.CompleteApplicationCloseReauth(ctx, request)
	if err != nil || proof.ProofJws != again.ProofJws || !proof.ExpiresAt.AsTime().Equal(again.ExpiresAt.AsTime()) {
		t.Fatal("nonstable replay", err)
	}
	claims := identityPayload(t, proof.ProofJws)
	if claims["application_id"] != applicationID || claims["purpose"] != "app.close" || claims["token_type"] != "APP_CLOSE_REAUTH" || claims["sub"] != registered.AuthId || claims["aud"] != "iwut-app-center" {
		t.Fatal("wrong proof", claims)
	}
	post := func(body string, want int) {
		t.Helper()
		r, _ := http.NewRequest("POST", "http://"+env[config.HTTPAddrEnv]+"/v1/application-close-reauth:complete", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("x-iwut-session", registered.Session.SessionToken)
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("HTTP %d want %d: %s", response.StatusCode, want, data)
		}
		if want == 200 && !bytes.Contains(data, []byte(proof.ProofJws)) {
			t.Fatal("HTTP replay proof drift")
		}
	}
	fields := map[string]any{"operationId": request.OperationId, "applicationId": request.ApplicationId, "signatureDer": base64.StdEncoding.EncodeToString(request.SignatureDer)}
	body, _ := json.Marshal(fields)
	post(string(body), 400)
	fields["currentPassword"] = nil
	body, _ = json.Marshal(fields)
	post(string(body), 400)
	fields["currentPassword"] = request.CurrentPassword
	body, _ = json.Marshal(fields)
	post(string(body), 200)
	fields["currentPassword"] = "wrong current password"
	body, _ = json.Marshal(fields)
	post(string(body), 401)
	// Online replay is fenced even if only the password revision is modified.
	if _, err = db.Collection(ma.PasswordCollection).UpdateOne(t.Context(), bson.M{"authId": registered.AuthId}, bson.M{"$inc": bson.M{"passwordRevision": int64(1)}}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.CompleteApplicationCloseReauth(ctx, request); status.Code(err) != codes.Unauthenticated {
		t.Fatal("password revision drift bypass", err)
	}
}
