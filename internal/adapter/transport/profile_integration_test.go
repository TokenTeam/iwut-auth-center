package transport

import (
	"context"
	"fmt"
	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	pb "iwut-auth-center/api/gen/go/auth_center/v1/user_profile"
	"iwut-auth-center/internal/adapter/catalog"
	ma "iwut-auth-center/internal/adapter/mongo"
	"iwut-auth-center/internal/config"
	"iwut-auth-center/internal/profile/domain"
	"iwut-auth-center/internal/profile/usecase"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProfileRealMongoAndListener(t *testing.T) {
	uri := os.Getenv("MONGODB_INTEGRATION_URI")
	if uri == "" {
		t.Skip("MONGODB_INTEGRATION_URI not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mongo, e := ma.NewClient(uri)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = mongo.Disconnect(context.Background()) }()
	db := mongo.Database(fmt.Sprintf("profile_listener_%d", time.Now().UnixNano()))
	defer func() { _ = db.Drop(context.Background()) }()
	if e = ma.EnsurePrincipalSchema(ctx, db); e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"user1", "user2"} {
		_, e = db.Collection(ma.PrincipalCollection).InsertOne(ctx, bson.M{"authId": id, "principalType": "USER", "accountStatus": "ACTIVE", "profile": bson.M{"entries": bson.A{}, "revision": int64(1), "updatedAt": time.Now()}})
		if e != nil {
			t.Fatal(e)
		}
	}
	repo, _ := ma.NewProfileRepository(db)
	cat, e := catalog.NewProfileCatalog(config.ProfileConfig{JSON: []byte(`{"definitions":[{"key":"flag","label":"Flag","description":"test fixture only","valueType":"BOOLEAN","constraints":{}}]}`)})
	if e != nil {
		t.Fatal(e)
	}
	key, verifier := userKey(t)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	server := kgrpc.NewServer(kgrpc.Listener(listener), kgrpc.Middleware(UserProfileIdentityMiddleware(verifier)), kgrpc.Options(grpc.MaxRecvMsgSize(domain.MaxMessageBytes), grpc.ForceServerCodec(NewProfileStrictCodec())))
	RegisterUserProfileServer(server, NewUserProfileServer(usecase.NewProfileService(repo, cat)))
	done := make(chan error, 1)
	go func() { done <- server.Start(context.Background()) }()
	defer func() { _ = server.Stop(context.Background()); <-done }()
	conn, e := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	client := pb.NewUserProfileServiceClient(conn)
	if _, e = client.GetOwnProfile(ctx, &pb.GetOwnProfileRequest{}); status.Code(e) != codes.Unauthenticated {
		t.Fatal("anonymous profile permitted", e)
	}
	auth := metadata.NewOutgoingContext(ctx, metadata.Pairs(UserIdentityHeader, signUser(t, key, userClaims("user1"))))
	schema, e := client.GetProfileEditingSchema(auth, &pb.GetProfileEditingSchemaRequest{})
	if e != nil || len(schema.Definitions) != 1 || schema.Limits.MaxFields != 64 {
		t.Fatal("schema", e)
	}
	rev := int64(1)
	res, e := client.EditOwnProfile(auth, &pb.EditOwnProfileRequest{ExpectedRevision: &rev, Set: []*pb.ProfileFieldAssignment{{Key: "flag", Value: &pb.ProfileValue{Value: &pb.ProfileValue_BooleanValue{BooleanValue: false}}}}})
	if e != nil || !res.Changed || res.Profile.Revision != 2 || res.Profile.Entries[0].Value.GetBooleanValue() != false {
		t.Fatal("edit false", e)
	}
	own, e := client.GetOwnProfile(auth, &pb.GetOwnProfileRequest{})
	if e != nil || own.Revision != 2 {
		t.Fatal("read", e)
	}
	other := metadata.NewOutgoingContext(ctx, metadata.Pairs(UserIdentityHeader, signUser(t, key, userClaims("user2"))))
	otherProfile, e := client.GetOwnProfile(other, &pb.GetOwnProfileRequest{})
	if e != nil || len(otherProfile.Entries) != 0 {
		t.Fatal("other user overwritten", e)
	}
	duplicate := metadata.NewOutgoingContext(ctx, metadata.Pairs(UserIdentityHeader, signUser(t, key, userClaims("user1")), UserIdentityHeader, signUser(t, key, userClaims("user1"))))
	if _, e = client.GetOwnProfile(duplicate, &pb.GetOwnProfileRequest{}); status.Code(e) != codes.Unauthenticated {
		t.Fatal("duplicate identity accepted", e)
	}
	if _, e = client.EditOwnProfile(auth, &pb.EditOwnProfileRequest{ExpectedRevision: &rev, Remove: []string{strings.Repeat("x", domain.MaxMessageBytes+1)}}); status.Code(e) != codes.ResourceExhausted {
		t.Fatal("oversize message accepted", e)
	}
}
