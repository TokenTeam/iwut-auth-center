package mongo

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"iwut-auth-center/internal/adapter/closereauthsigner"
	reauthd "iwut-auth-center/internal/applicationclosereauth/domain"
	reauthuc "iwut-auth-center/internal/applicationclosereauth/usecase"
	closured "iwut-auth-center/internal/applicationclosure/domain"
	closureuc "iwut-auth-center/internal/applicationclosure/usecase"
)

func TestApplicationClosureMongoPermanentIdempotentTombstone(t *testing.T) {
	f := newAuthenticationFixture(t)
	if err := EnsureApplicationClosureSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	repository, _ := NewApplicationClosureRepository(f.r)
	service := closureuc.New(repository)
	applicationID := uuid.NewString()
	closureID, _ := uuid.NewV7()
	started := time.Now().UTC().Truncate(time.Millisecond)
	first, err := service.Apply(t.Context(), applicationID, closureID.String(), started, "app-center")
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Apply(t.Context(), applicationID, closureID.String(), started, "app-center")
	if err != nil || first != second {
		t.Fatalf("idempotent Apply = %#v, %v", second, err)
	}
	got, err := service.Get(t.Context(), applicationID, closureID.String())
	if err != nil || got != first {
		t.Fatalf("Get = %#v, %v", got, err)
	}
	other, _ := uuid.NewV7()
	if _, err = service.Apply(t.Context(), applicationID, other.String(), started, "app-center"); !errors.Is(err, closured.ErrConflict) {
		t.Fatalf("different closure = %v", err)
	}
	if _, err = service.Apply(t.Context(), applicationID, closureID.String(), started.Add(time.Millisecond), "app-center"); !errors.Is(err, closured.ErrConflict) {
		t.Fatalf("different time = %v", err)
	}
	if n, _ := f.r.database.Collection(ApplicationClosureAuditCollection).CountDocuments(t.Context(), bson.M{}); n != 1 {
		t.Fatalf("audit count = %d", n)
	}
	if err = VerifyApplicationClosureConsistency(t.Context(), f.r.database); err != nil {
		t.Fatalf("restore consistency = %v", err)
	}
	if n, _ := f.r.database.Collection(ApplicationClosureSecurityEventCollection).CountDocuments(t.Context(), bson.M{}); n != 2 {
		t.Fatalf("conflict security event count = %d", n)
	}
}

func TestApplicationClosureMongoRejectsOrphanReceiptOnRestore(t *testing.T) {
	f := newAuthenticationFixture(t)
	if err := EnsureApplicationClosureSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	_, err := f.r.database.Collection(ApplicationClosureAuditCollection).InsertOne(t.Context(), bson.M{"applicationId": uuid.NewString(), "closureId": uuid.NewString(), "receiptId": uuid.NewString(), "closingStartedAt": now, "appliedAt": now, "callerServiceId": "app-center", "action": "APPLICATION_CLOSED"})
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyApplicationClosureConsistency(t.Context(), f.r.database); !errors.Is(err, closured.ErrInconsistent) {
		t.Fatalf("consistency = %v", err)
	}
}

func TestApplicationClosureMongoConcurrentApplyHasOneReceipt(t *testing.T) {
	f := newAuthenticationFixture(t)
	if err := EnsureApplicationClosureSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	repository, _ := NewApplicationClosureRepository(f.r)
	service := closureuc.New(repository)
	applicationID := uuid.NewString()
	closureID, _ := uuid.NewV7()
	started := time.Now().UTC().Truncate(time.Millisecond)
	var wg sync.WaitGroup
	results := make(chan string, 8)
	failures := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := service.Apply(context.Background(), applicationID, closureID.String(), started, "app-center")
			if err != nil {
				failures <- err
				return
			}
			results <- v.ReceiptID
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	want := ""
	count := 0
	for receipt := range results {
		count++
		if want == "" {
			want = receipt
		}
		if receipt != want {
			t.Fatalf("unstable receipt %q != %q", receipt, want)
		}
	}
	if count != 8 {
		t.Fatalf("successes = %d", count)
	}
}

func TestApplicationCloseReauthMongoSameSessionDeviceAndStableProof(t *testing.T) {
	f := newAuthenticationFixture(t)
	if err := EnsureApplicationCloseReauthSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	session := f.login(t)
	digest, err := f.p.TokenDigest(session.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	repository, _ := NewApplicationCloseReauthRepository(f.r)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := closereauthsigner.New("close-proof-key", key)
	service, err := reauthuc.New(repository, f.p, signer, "https://auth.example.test")
	if err != nil {
		t.Fatal(err)
	}
	applicationID := uuid.NewString()
	challenge, err := service.Begin(t.Context(), digest, applicationID)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := reauthuc.SigningPayload(challenge.OperationID, applicationID, challenge.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	sig := signCloseReauth(t, f.key, payload)
	proof, err := service.Complete(t.Context(), digest, challenge.OperationID, applicationID, sig)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := service.Complete(t.Context(), digest, challenge.OperationID, applicationID, sig)
	if err != nil || retry != proof {
		t.Fatalf("retry = %#v, %v", retry, err)
	}
	header, claims := decodeCloseProof(t, proof.JWS, &key.PublicKey)
	if header["typ"] != "iwut-app-close-reauth+jwt" || claims["aud"] != "iwut-app-center" || claims["purpose"] != "app.close" || claims["token_type"] != "APP_CLOSE_REAUTH" || claims["application_id"] != applicationID || claims["sub"] != f.c.AuthID {
		t.Fatalf("wrong proof: %#v %#v", header, claims)
	}
	if int64(claims["exp"].(float64))-int64(claims["iat"].(float64)) != 300 || int64(claims["iat"].(float64))-int64(claims["nbf"].(float64)) != 30 || claims["iat"] != claims["auth_time"] {
		t.Fatalf("wrong proof times: %#v", claims)
	}
	var stored bson.Raw
	if err = f.r.database.Collection(ApplicationCloseReauthOperationCollection).FindOne(t.Context(), bson.M{"operationid": challenge.OperationID}).Decode(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.Lookup("proofjws").Type != 0 || stored.Lookup("signature").Type != 0 || stored.Lookup("signaturedigest").Type != bson.TypeBinary {
		t.Fatal("proof or signature persisted, or signature digest missing")
	}
	var audits []bson.M
	cursor, _ := f.r.database.Collection(ApplicationCloseReauthAuditCollection).Find(t.Context(), bson.M{})
	if err = cursor.All(t.Context(), &audits); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(audits)
	if strings.Contains(string(encoded), proof.JWS) || strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(challenge.Challenge)) || strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(sig)) {
		t.Fatal("secret material entered audit")
	}
}

func TestApplicationCloseReauthMongoRejectsDifferentSessionAndRevocation(t *testing.T) {
	f := newAuthenticationFixture(t)
	if err := EnsureApplicationCloseReauthSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	first := f.login(t)
	second := f.login(t)
	firstDigest, _ := f.p.TokenDigest(first.SessionToken)
	secondDigest, _ := f.p.TokenDigest(second.SessionToken)
	repository, _ := NewApplicationCloseReauthRepository(f.r)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := closereauthsigner.New("close-proof-key", key)
	service, _ := reauthuc.New(repository, f.p, signer, "issuer")
	app := uuid.NewString()
	challenge, err := service.Begin(t.Context(), firstDigest, app)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := reauthuc.SigningPayload(challenge.OperationID, app, challenge.Challenge)
	sig := signCloseReauth(t, f.key, payload)
	if _, err = service.Complete(t.Context(), secondDigest, challenge.OperationID, app, sig); !errors.Is(err, reauthd.ErrFailed) {
		t.Fatalf("different Session = %v", err)
	}
	if _, err = f.r.database.Collection(SessionCollection).UpdateOne(t.Context(), bson.M{"sessionId": first.SessionID}, bson.M{"$set": bson.M{"revokedAt": time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Complete(t.Context(), firstDigest, challenge.OperationID, app, sig); !errors.Is(err, reauthd.ErrFailed) {
		t.Fatalf("revoked Session = %v", err)
	}
}

func TestApplicationCloseReauthMongoPersistsBoundedFailureWithoutSecret(t *testing.T) {
	f := newAuthenticationFixture(t)
	if err := EnsureApplicationCloseReauthSchema(t.Context(), f.r.database); err != nil {
		t.Fatal(err)
	}
	session := f.login(t)
	digest, _ := f.p.TokenDigest(session.SessionToken)
	repository, _ := NewApplicationCloseReauthRepository(f.r)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := closereauthsigner.New("close-proof-key", key)
	service, _ := reauthuc.New(repository, f.p, signer, "issuer")
	app := uuid.NewString()
	challenge, err := service.Begin(t.Context(), digest, app)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := reauthuc.SigningPayload(challenge.OperationID, app, challenge.Challenge)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signature := signCloseReauth(t, wrongKey, payload)
	if _, err = service.Complete(t.Context(), digest, challenge.OperationID, app, signature); !errors.Is(err, reauthd.ErrFailed) {
		t.Fatalf("invalid signature = %v", err)
	}
	var stored closeReauthDocument
	if err = f.r.database.Collection(ApplicationCloseReauthOperationCollection).FindOne(t.Context(), bson.M{"operationid": challenge.OperationID}).Decode(&stored); err != nil {
		t.Fatal(err)
	}
	if stored.FailedAttempts != 1 || len(stored.SignatureDigest) != 0 {
		t.Fatalf("failed operation = %#v", stored)
	}
	var audit bson.M
	if err = f.r.database.Collection(ApplicationCloseReauthAuditCollection).FindOne(t.Context(), bson.M{"operationId": challenge.OperationID, "result": "SIGNATURE_REJECTED"}).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(audit)
	if strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(signature)) || strings.Contains(string(encoded), base64.StdEncoding.EncodeToString(challenge.Challenge)) {
		t.Fatal("challenge or signature entered failed audit")
	}
}

func signCloseReauth(t *testing.T, key *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func decodeCloseProof(t *testing.T, raw string, key *rsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatal("invalid compact JWS")
	}
	decode := func(raw string) map[string]any {
		data, err := base64.RawURLEncoding.Strict().DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err = json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err = rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
	return decode(parts[0]), decode(parts[1])
}
