package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"os"
	"testing"
	"time"

	api "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/authentication"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"iwut-auth-center/internal/adapter/associationcrypto"
	"iwut-auth-center/internal/adapter/deviceprotocol"
	mongoadapter "iwut-auth-center/internal/adapter/mongo"
	auth "iwut-auth-center/internal/authentication/domain"
	"iwut-auth-center/internal/registration/domain"
	"iwut-auth-center/internal/registration/usecase"
)

type registrationTestServer struct {
	api.UnimplementedAuthenticationServiceServer
	handler *RegistrationHandler
}

func (s *registrationTestServer) BeginUserRegistration(ctx context.Context, r *api.BeginUserRegistrationRequest) (*api.AuthenticationChallenge, error) {
	return s.handler.BeginUserRegistration(ctx, r)
}
func (s *registrationTestServer) CompleteUserRegistration(ctx context.Context, r *api.CompleteUserRegistrationRequest) (*api.UserRegistrationResult, error) {
	return s.handler.CompleteUserRegistration(ctx, r)
}

func TestRegistrationGeneratedClientRealMongoAndCrypto(t *testing.T) {
	uri := os.Getenv("MONGODB_INTEGRATION_URI")
	if uri == "" {
		t.Skip("MONGODB_INTEGRATION_URI is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mc, err := drivermongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := mc.Database("uc006_rpc_" + uuid.NewString())
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = mc.Disconnect(context.Background()) })
	var hello bson.M
	if err = db.RunCommand(ctx, bson.M{"hello": 1}).Decode(&hello); err != nil {
		t.Fatal(err)
	}
	if _, ok := hello["setName"]; !ok {
		t.Skip("registration RPC requires replica set")
	}
	for _, ensure := range []func(context.Context, *drivermongo.Database) error{mongoadapter.EnsurePrincipalSchema, mongoadapter.EnsureAuthenticationSchema, mongoadapter.EnsureAssociationSchema} {
		if err := ensure(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	authRepo, _ := mongoadapter.NewAuthenticationRepository(db, 10000, 5)
	repo, _ := mongoadapter.NewRegistrationRepository(db, authRepo)
	crypt, _ := associationcrypto.New(associationcrypto.Key{Version: "test", Encrypt: bytes.Repeat([]byte{1}, 32), Lookup: bytes.Repeat([]byte{2}, 32)}, nil)
	protocol, _ := deviceprotocol.New("iwut-auth-center:test")
	limiter, _ := deviceprotocol.NewLimiter(deviceprotocol.DefaultRateLimits())
	u, err := usecase.NewRegistration(repo, protocol, crypt, limiter, "iwut-auth-center:test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	api.RegisterAuthenticationServiceServer(server, &registrationTestServer{handler: NewRegistrationHandler(u)})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := api.NewAuthenticationServiceClient(conn)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := &api.BeginUserRegistrationRequest{CredentialProposal: &api.CredentialRegistrationProposal{ProtocolVersion: auth.ProtocolVersion, PublicKey: elliptic.Marshal(elliptic.P256(), key.X, key.Y)}, Association: &api.StudentAssociationDeclaration{SchemeVersion: domain.AssociationScheme, AssociationToken: bytes.Repeat([]byte{7}, 32)}}
	challenge, err := client.BeginUserRegistration(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(challenge.SigningPayload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	complete := &api.CompleteUserRegistrationRequest{OperationId: challenge.OperationId, Proof: &api.CredentialProof{Signature: signature}}
	result, err := client.CompleteUserRegistration(ctx, complete)
	if err != nil {
		t.Fatal(err)
	}
	if result.AuthId == "" || result.CredentialId == "" || len(result.Session.SessionToken) != 43 || result.Session.AuthId != result.AuthId {
		t.Fatal("invalid result")
	}
	digest, _ := protocol.TokenDigest(result.Session.SessionToken)
	if _, err = authRepo.CheckSession(ctx, digest, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err = client.CompleteUserRegistration(ctx, complete)
	s := status.Convert(err)
	if s.Code() != codes.AlreadyExists {
		t.Fatal("replay status", s.Code())
	}
	found := false
	for _, d := range s.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.Reason == "REGISTRATION_ALREADY_COMPLETED" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing machine-readable reason")
	}
	_, err = client.BeginUserRegistration(ctx, &api.BeginUserRegistrationRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatal("empty registration accepted")
	}
	request.CredentialProposal.ProtocolVersion = "not-supported"
	_, err = client.BeginUserRegistration(ctx, request)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatal("unsupported protocol accepted")
	}
}
