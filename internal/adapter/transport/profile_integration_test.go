package transport

import (
	"context"
	"fmt"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

type fixedAcademicYear int32

func (year fixedAcademicYear) CurrentAcademicYear(context.Context, time.Time) (int32, error) {
	return int32(year), nil
}

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
		_, e = db.Collection(ma.PrincipalCollection).InsertOne(ctx, bson.M{"authId": id, "principalType": "USER", "accountStatus": "ACTIVE", "accountRevision": int64(1), "minimumCredentialRevision": int64(1), "profile": bson.M{"entries": bson.A{}, "revision": int64(1), "updatedAt": time.Now()}})
		if e != nil {
			t.Fatal(e)
		}
	}
	repo, _ := ma.NewProfileRepository(db)
	cat, e := catalog.NewProfileCatalog(config.ProfileConfig{JSON: []byte(`{"definitions":[{"key":"flag","label":"Flag","description":"test fixture only","valueType":"BOOLEAN","constraints":{}},{"key":"education.campus_areas","label":"Campus","description":"test fixture only","valueType":"STRING_SET","constraints":{"options":[{"value":"NANHU","label":"南湖"},{"value":"JIANHU","label":"鉴湖"}],"minItems":1,"maxItems":2}},{"key":"education.current_grade","label":"Grade","description":"test fixture only","valueType":"ACADEMIC_GRADE","constraints":{}}]}`)})
	if e != nil {
		t.Fatal(e)
	}
	key, verifier := userKey(t)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	server := kgrpc.NewServer(kgrpc.Listener(listener), kgrpc.Middleware(UserProfileIdentityMiddleware(verifier)), kgrpc.Options(grpc.MaxRecvMsgSize(domain.MaxMessageBytes), grpc.ForceServerCodec(NewProfileStrictCodec())))
	profileService := usecase.NewProfileService(repo, cat, fixedAcademicYear(2026))
	RegisterUserProfileServer(server, NewUserProfileServer(profileService))
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
	if e != nil || len(schema.Definitions) != 3 || schema.Limits.MaxFields != 64 || schema.CurrentAcademicYear == nil || schema.GetCurrentAcademicYear() != 2026 {
		t.Fatal("schema", e)
	}
	rev := int64(1)
	res, e := client.EditOwnProfile(auth, &pb.EditOwnProfileRequest{ExpectedRevision: &rev, Set: []*pb.ProfileFieldAssignment{
		{Key: "flag", Value: &pb.ProfileValue{Value: &pb.ProfileValue_BooleanValue{BooleanValue: false}}},
		{Key: "education.campus_areas", Value: &pb.ProfileValue{Value: &pb.ProfileValue_StringSetValue{StringSetValue: &pb.StringSetValue{Values: []string{"NANHU", "JIANHU"}}}}},
		{Key: "education.current_grade", Value: &pb.ProfileValue{Value: &pb.ProfileValue_AcademicGradeValue{AcademicGradeValue: &pb.AcademicGradeValue{Stage: "UNDERGRADUATE", Year: 3, FinalYear: 4, AcademicYear: 2026}}}},
	}})
	if e != nil || !res.Changed || res.Profile.Revision != 2 || len(res.Profile.Entries) != 3 {
		t.Fatal("edit false", e)
	}
	byKey := map[string]*pb.ProfileValue{}
	for _, entry := range res.Profile.Entries {
		byKey[entry.Key] = entry.Value
	}
	if got := byKey["education.campus_areas"].GetStringSetValue().Values; len(got) != 2 || got[0] != "JIANHU" || got[1] != "NANHU" {
		t.Fatal("string set not canonical", got)
	}
	grade := byKey["education.current_grade"].GetAcademicGradeValue()
	if grade == nil || grade.ConfirmedAt == nil || grade.AcademicYear != 2026 || grade.Year != 3 {
		t.Fatal("grade anchor missing", grade)
	}
	own, e := client.GetOwnProfile(auth, &pb.GetOwnProfileRequest{})
	if e != nil || own.Revision != 2 || len(own.Entries) != 3 {
		t.Fatal("read", e)
	}
	rev = 2
	if _, e = client.EditOwnProfile(auth, &pb.EditOwnProfileRequest{ExpectedRevision: &rev, Set: []*pb.ProfileFieldAssignment{{Key: "education.current_grade", Value: &pb.ProfileValue{Value: &pb.ProfileValue_AcademicGradeValue{AcademicGradeValue: &pb.AcademicGradeValue{Stage: "UNDERGRADUATE", Year: 3, FinalYear: 4, AcademicYear: 2026, ConfirmedAt: grade.ConfirmedAt}}}}}}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("client confirmedAt accepted", e)
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
