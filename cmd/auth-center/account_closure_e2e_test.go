package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_closure"
	authpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
)

func TestAccountClosureActualAppWire(t *testing.T) {
	ledger := t.TempDir()
	if err := os.Chmod(ledger, 0700); err != nil {
		t.Fatal(err)
	}
	f := newOwnerExitWireFixture(t, map[string]string{"AUTH_ACCOUNT_CLOSURE_ENABLED": "true", "AUTH_CLOSURE_DATA_POLICY_READY": "true", "AUTH_TERMINATION_LEDGER_DIR": ledger, "AUTH_ACCOUNT_CLOSURE_WORKER_INTERVAL": "10ms", "AUTH_ACCOUNT_CLOSURE_READ_PER_MINUTE": "10000", "AUTH_ACCOUNT_CLOSURE_WRITE_PER_MINUTE": "10000"})
	client := pb.NewAccountClosureServiceClient(f.Conn)
	auth := authpb.NewAuthenticationServiceClient(f.Conn)
	for _, disabled := range []bool{false, true} {
		name := "active-native"
		if disabled {
			name = "disabled-http"
		}
		t.Run(name, func(t *testing.T) {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			assoc := make([]byte, 32)
			_, _ = rand.Read(assoc)
			user, _ := registerUser(t, f.Conn, key, assoc)
			if disabled {
				_, e := f.DB.Collection(ma.PrincipalCollection).UpdateOne(t.Context(), bson.M{"authId": user.AuthId}, bson.M{"$set": bson.M{"accountStatus": "DISABLED", "accountRevision": int64(2)}})
				if e != nil {
					t.Fatal(e)
				}
			}
			begin := &pb.BeginAccountClosureRequest{RequestId: uuid.NewString(), CredentialLocator: &pb.BeginAccountClosureRequest_CredentialId{CredentialId: user.CredentialId}}
			// Existing Session is deliberately insufficient and cannot be mixed in.
			if _, e := client.BeginAccountClosure(sessionCallContext(t.Context(), user.Session.SessionToken), begin); status.Code(e) != codes.Unauthenticated {
				t.Fatalf("mixed Session: %v", e)
			}
			var challenge *pb.AccountClosureChallenge
			if disabled {
				challenge = &pb.AccountClosureChallenge{}
				closureHTTP(t, f, "begin", begin, "", "", challenge, http.StatusOK)
			} else {
				var e error
				challenge, e = client.BeginAccountClosure(t.Context(), begin)
				if e != nil {
					t.Fatal(e)
				}
			}
			if !disabled {
				candidate := map[string]string{}
				for k, v := range f.Env {
					candidate[k] = v
				}
				candidate["AUTH_ACCOUNT_CLOSURE_ENABLED"] = "false"
				delete(candidate, "AUTH_TERMINATION_LEDGER_DIR")
				c, e := config.Load(func(k string) (string, bool) { v, ok := candidate[k]; return v, ok })
				if e != nil {
					t.Fatal(e)
				}
				if _, cleanup, e := wireApp(c); e == nil {
					cleanup()
					t.Fatal("pending proof accepted without closure runtime")
				}
			}
			prepare := &pb.PrepareAccountClosureRequest{OperationId: challenge.OperationId, Signature: signDevice(t, key, challenge.SigningPayload), CurrentPassword: "a long fixture password 123"}
			missingPassword := proto.Clone(prepare).(*pb.PrepareAccountClosureRequest)
			missingPassword.CurrentPassword = ""
			if _, err := client.PrepareAccountClosure(t.Context(), missingPassword); status.Code(err) != codes.InvalidArgument {
				t.Fatal("native signature-only Prepare was not rejected", err)
			}
			closureHTTP(t, f, "prepare", missingPassword, "", "", nil, http.StatusBadRequest)
			wrongPassword := proto.Clone(prepare).(*pb.PrepareAccountClosureRequest)
			wrongPassword.CurrentPassword = "an incorrect fixture password"
			if _, err := client.PrepareAccountClosure(t.Context(), wrongPassword); status.Code(err) != codes.Unauthenticated {
				t.Fatal("native wrong password was not rejected", err)
			}
			closureHTTP(t, f, "prepare", wrongPassword, "", "", nil, http.StatusUnauthorized)
			if n, err := f.DB.Collection(ma.OwnerExitCollection).CountDocuments(t.Context(), bson.M{"operationId": challenge.OperationId}); err != nil || n != 0 {
				t.Fatal("failed password created an App ownership barrier", n, err)
			}
			var ready *pb.AccountClosurePreparation
			if disabled {
				ready = &pb.AccountClosurePreparation{}
				closureHTTP(t, f, "prepare", prepare, "", "", ready, http.StatusOK)
			} else {
				var e error
				ready, e = client.PrepareAccountClosure(t.Context(), prepare)
				if e != nil {
					t.Fatal(e)
				}
			}
			if ready.Outcome != pb.PreparationOutcome_PREPARATION_OUTCOME_READY || ready.Preview.GetAuthId() != user.AuthId || !ready.Preview.GetIrreversible() || ready.ConfirmationToken == "" || ready.ReceiptToken == "" {
				t.Fatalf("prepare: %v", ready)
			}
			confirm := &pb.ConfirmAccountClosureRequest{OperationId: challenge.OperationId, Confirmation: "CLOSE_ACCOUNT", PolicyVersion: challenge.PolicyVersion}
			wrong := metadata.AppendToOutgoingContext(t.Context(), "x-iwut-closure-receipt", ready.ReceiptToken)
			if _, e := client.ConfirmAccountClosure(wrong, confirm); status.Code(e) != codes.Unauthenticated {
				t.Fatalf("receipt cannot confirm: %v", e)
			}
			ctx := metadata.AppendToOutgoingContext(t.Context(), "x-iwut-closure-confirmation", ready.ConfirmationToken)
			if disabled {
				closureHTTP(t, f, "confirm", confirm, "x-iwut-closure-confirmation", ready.ConfirmationToken, &pb.AccountClosureStatus{}, http.StatusOK)
			} else {
				if _, e := client.ConfirmAccountClosure(ctx, confirm); e != nil {
					t.Fatal(e)
				}
			}
			// Retrying cannot increment the terminal generation a second time.
			if _, e := client.ConfirmAccountClosure(ctx, confirm); e != nil {
				t.Fatal(e)
			}
			receiptCtx := metadata.AppendToOutgoingContext(t.Context(), "x-iwut-closure-receipt", ready.ReceiptToken)
			deadline := time.Now().Add(30 * time.Second)
			for {
				state, e := client.GetAccountClosure(receiptCtx, &pb.GetAccountClosureRequest{OperationId: challenge.OperationId})
				if e != nil {
					t.Fatal(e)
				}
				if state.State == pb.ClosureState_CLOSURE_STATE_CLEANUP_COMPLETE {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("cleanup failed to finish: %v", state)
				}
				time.Sleep(20 * time.Millisecond)
			}
			var raw bson.Raw
			if e := f.DB.Collection(ma.PrincipalCollection).FindOne(t.Context(), bson.M{"authId": user.AuthId}).Decode(&raw); e != nil {
				t.Fatal(e)
			}
			fields, _ := raw.Elements()
			expected := int64(2)
			if disabled {
				expected = 3
			}
			if len(fields) != 7 || raw.Lookup("accountStatus").StringValue() != "CLOSED" || raw.Lookup("accountRevision").Int64() != expected {
				t.Fatalf("invalid minimal tombstone: %v", raw)
			}
			if _, e := auth.RevokeOwnCredential(sessionCallContext(t.Context(), user.Session.SessionToken), &authpb.RevokeOwnCredentialRequest{CredentialId: user.CredentialId}); status.Code(e) != codes.Unauthenticated {
				t.Fatalf("old Session survived: %v", e)
			}
			closureHTTP(t, f, "get", &pb.GetAccountClosureRequest{OperationId: challenge.OperationId}, "x-iwut-closure-receipt", ready.ReceiptToken, &pb.AccountClosureStatus{}, http.StatusOK)
		})
	}
	// Runtime reconciliation survives disabling public entry points. Removing the
	// independent ledger configuration altogether must fail before listening.
	env := map[string]string{}
	for k, v := range f.Env {
		env[k] = v
	}
	env["AUTH_ACCOUNT_CLOSURE_ENABLED"] = "false"
	load := func() config.Config {
		c, e := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	_, cleanup, e := wireApp(load())
	if e != nil {
		t.Fatalf("disabled public gate stopped recovery: %v", e)
	}
	cleanup()
	delete(env, "AUTH_TERMINATION_LEDGER_DIR")
	if _, cleanup, e = wireApp(load()); e == nil {
		cleanup()
		t.Fatal("CLOSED accounts accepted without ledger runtime")
	}
	// CLI uses only Mongo and ledger configuration; it does not load identity keys.
	t.Setenv(config.MongoURIEnv, f.Env[config.MongoURIEnv])
	t.Setenv(config.MongoDatabaseEnv, f.DB.Name())
	t.Setenv("AUTH_TERMINATION_LEDGER_DIR", ledger)
	var output bytes.Buffer
	if e := reconcileAccountClosures(nil, &output); e != nil {
		t.Fatal(e)
	}
	var result map[string]bool
	if json.Unmarshal(output.Bytes(), &result) != nil || !result["reconciled"] {
		t.Fatalf("CLI: %s", output.String())
	}
}

func closureHTTP(t *testing.T, f *ownerExitWireFixture, action string, in proto.Message, header, value string, out proto.Message, want int) {
	t.Helper()
	data, e := protojson.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	req, e := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+f.Env[config.HTTPAddrEnv]+"/v1/account-closures:"+action, bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Content-Type", "application/json")
	if header != "" {
		req.Header.Set(header, value)
	}
	response, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	body, e := io.ReadAll(response.Body)
	if e != nil {
		t.Fatal(e)
	}
	if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("HTTP %s: %d %s", action, response.StatusCode, body)
	}
	if out != nil {
		if e = protojson.Unmarshal(body, out); e != nil {
			t.Fatal(e)
		}
	}
}
