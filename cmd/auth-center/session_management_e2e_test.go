package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	authv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/session_management"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestE2E_SessionManagement_ProductionWire(t *testing.T) {
	uri := os.Getenv(mongoIntegrationURIEnv)
	if uri == "" {
		t.Skip("run make test-mongo")
	}
	_, callers := testServiceCallerRegistry(t)
	// Separate issuer key: this is a fixture for the already defined trusted-user
	// boundary, not an implementation of the future Session-to-JWS issuer.
	identityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	publicDER, err := x509.MarshalPKIXPublicKey(&identityKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "identity.pem")
	catalogFile := filepath.Join(dir, "profile.json")
	for path, data := range map[string][]byte{keyFile: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), catalogFile: []byte(`{"definitions":[{"key":"test.nickname","label":"Test nickname","description":"Fixture only","valueType":"STRING","constraints":{"maxLength":32}}]}`)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	keysJSON, _ := json.Marshal(map[string]string{"test": keyFile})
	dbName := fmt.Sprintf("iwut_user_wire_%d", time.Now().UnixNano())
	env := map[string]string{config.UserEndpointsEnabledEnv: "true", config.MongoURIEnv: uri, config.MongoDatabaseEnv: dbName, config.ServiceCallersEnv: callers, config.HTTPAddrEnv: reserveAddress(t), config.GRPCAddrEnv: reserveAddress(t), "AUTH_AUTHENTICATION_SERVICE_ID": "iwut-auth-center:test", "AUTH_SESSION_TTL": "24h", "AUTH_ASSOC_KEY_VERSION": "v1", "AUTH_PROFILE_CATALOG_FILE": catalogFile, "AUTH_USER_IDENTITY_ISSUER": "test-auth-issuer", "AUTH_USER_IDENTITY_PUBLIC_KEYS_JSON": string(keysJSON)}
	setKeys := func(version string, enc, lookup byte) {
		env["AUTH_ASSOC_KEY_VERSION"] = version
		env["AUTH_ASSOC_ENCRYPT_KEY"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{enc}, 32))
		env["AUTH_ASSOC_LOOKUP_KEY"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{lookup}, 32))
	}
	setKeys("v1", 1, 2)
	enableEmailRegistrationFixture(t, env)
	load := func() config.Config {
		t.Helper()
		c, e := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	mongoClient, err := mongoadapter.NewClient(uri)
	if err != nil {
		t.Fatal(err)
	}
	database := mongoClient.Database(dbName)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = database.Drop(ctx)
		_ = mongoClient.Disconnect(ctx)
	})

	env["AUTH_SESSION_MANAGEMENT_ENABLED"] = "true"
	app, cleanup, err := wireApp(load())
	if err != nil {
		t.Fatal(err)
	}
	connection, stop := startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])

	defer stop()
	authClient := authv1.NewAuthenticationServiceClient(connection)
	client := pb.NewSessionManagementServiceClient(connection)
	device, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	association := sha256.Sum256([]byte("same-student"))
	first, _ := registerUser(t, connection, device, association[:])
	second := loginUser(t, authClient, device, first.CredentialId)
	otherDevice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := registerUser(t, connection, otherDevice, association[:])
	ctx := sessionCallContext(t.Context(), first.Session.SessionToken)
	// Pin an older use time to make accidental authentication middleware touches visible.
	lastUsed := time.Now().UTC().Truncate(time.Millisecond)
	if _, e := database.Collection(mongoadapter.SessionCollection).UpdateMany(t.Context(), bson.M{"authId": first.AuthId}, bson.M{"$set": bson.M{"lastUsedAt": lastUsed}}); e != nil {
		t.Fatal(e)
	}
	time.Sleep(20 * time.Millisecond)
	page, e := client.ListOwnSessions(ctx, &pb.ListOwnSessionsRequest{})
	if e != nil || len(page.GetSessions()) != 2 {
		t.Fatalf("list: %v %v", page, e)
	}
	current := page.CurrentSessionId
	var target string
	for _, row := range page.Sessions {
		if row.IsCurrent {
			if row.SessionId != current {
				t.Fatal("current mismatch")
			}
		} else {
			target = row.SessionId
		}
		if !row.LastUsedAt.AsTime().Equal(lastUsed) {
			t.Fatal("list touched LRU")
		}
	}
	var caller bson.M
	if e = database.Collection(mongoadapter.SessionCollection).FindOne(t.Context(), bson.M{"sessionId": current}).Decode(&caller); e != nil {
		t.Fatal(e)
	}
	if caller["lastUsedAt"] != bson.NewDateTimeFromTime(lastUsed) {
		t.Fatal("persisted LRU touched")
	}
	otherPage, e := client.ListOwnSessions(sessionCallContext(t.Context(), other.Session.SessionToken), &pb.ListOwnSessionsRequest{})
	if e != nil || len(otherPage.GetSessions()) != 1 {
		t.Fatal(otherPage, e)
	}
	// HTTP generated schema shares the same account boundary and batch semantics.
	send := func(action, body string, want int) *pb.OwnSessionPage {
		t.Helper()
		r, _ := http.NewRequest("POST", "http://"+env[config.HTTPAddrEnv]+"/v1/users/me/sessions:"+action, strings.NewReader(body))
		r.Header.Set("content-type", "application/json")
		r.Header.Set("x-iwut-session", first.Session.SessionToken)
		res, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		data, _ := io.ReadAll(res.Body)
		if res.StatusCode != want || res.Header.Get("cache-control") != "no-store" {
			t.Fatalf("HTTP: %d %s %v", res.StatusCode, data, res.Header)
		}
		if action == "list" && want == 200 {
			p := new(pb.OwnSessionPage)
			if e = protojson.Unmarshal(data, p); e != nil {
				t.Fatal(e)
			}
			return p
		}
		return nil
	}
	p := send("list", `{"pageSize":1}`, 200)
	if len(p.Sessions) != 1 || p.NextCursor == "" {
		t.Fatal(p)
	}
	p = send("list", fmt.Sprintf(`{"pageSize":1,"cursor":%q}`, p.NextCursor), 200)
	if len(p.Sessions) != 1 || p.NextCursor != "" {
		t.Fatal(p)
	}
	send("revoke", fmt.Sprintf(`{"sessionIds":[%q,%q]}`, target, current), 400)
	if _, e = client.ListOwnSessions(sessionCallContext(t.Context(), second.SessionToken), &pb.ListOwnSessionsRequest{}); e != nil {
		t.Fatal("atomic current rejection", e)
	}
	targets := fmt.Sprintf(`{"sessionIds":[%q,%q,%q]}`, target, otherPage.CurrentSessionId, uuid.NewString())
	send("revoke", targets, 200)
	send("revoke", targets, 200)
	if _, e = client.ListOwnSessions(sessionCallContext(t.Context(), second.SessionToken), &pb.ListOwnSessionsRequest{}); status.Code(e) != codes.Unauthenticated {
		t.Fatal("revoked still authenticates", e)
	}
	if _, e = client.ListOwnSessions(sessionCallContext(t.Context(), other.Session.SessionToken), &pb.ListOwnSessionsRequest{}); e != nil {
		t.Fatal("association account affected", e)
	}
	fresh := loginUser(t, authClient, device, first.CredentialId)
	send("revoke", targets, 200)
	if _, e = client.ListOwnSessions(sessionCallContext(t.Context(), fresh.SessionToken), &pb.ListOwnSessionsRequest{}); e != nil {
		t.Fatal("retry revoked fresh login", e)
	}
	count, e := database.Collection(mongoadapter.SessionManagementAuditCollection).CountDocuments(t.Context(), bson.M{})
	if e != nil || count != 1 {
		t.Fatal("idempotent audit", count, e)
	}
	stop()
	env["AUTH_SESSION_MANAGEMENT_ENABLED"] = "false"
	env[config.HTTPAddrEnv] = reserveAddress(t)
	env[config.GRPCAddrEnv] = reserveAddress(t)
	app, cleanup, e = wireApp(load())
	if e != nil {
		t.Fatal(e)
	}
	connection, stop = startUserApp(t, app, cleanup, env[config.GRPCAddrEnv])
	defer stop()
	if _, e = pb.NewSessionManagementServiceClient(connection).ListOwnSessions(ctx, &pb.ListOwnSessionsRequest{}); status.Code(e) != codes.Unimplemented {
		t.Fatal("disabled endpoint exposed", e)
	}
}
