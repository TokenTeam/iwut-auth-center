package transport

import (
	"errors"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/campus_certification"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	d "iwut-auth-center/internal/campuscertification/domain"
	"testing"
)

func TestCampusWireRejectsDuplicatesUnknownTypesUTF8(t *testing.T) {
	valid, _ := proto.Marshal(&pb.BeginOwnCampusCertificationRequest{RequestId: "request", Email: "name@whut.edu.cn"})
	if err := campusCertificationWire(valid, &pb.BeginOwnCampusCertificationRequest{}); err != nil {
		t.Fatal(err)
	}
	duplicate := protowire.AppendString(protowire.AppendTag(append([]byte(nil), valid...), 1, protowire.BytesType), "second")
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 3, protowire.VarintType), 1)
	wrongType := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1)
	invalidUTF8 := protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), []byte{0xff})
	for _, wire := range [][]byte{duplicate, unknown, wrongType, invalidUTF8, {0x0a, 0xff}, make([]byte, 16*1024+1)} {
		if err := campusCertificationWire(wire, &pb.BeginOwnCampusCertificationRequest{}); !errors.Is(err, d.ErrInvalid) {
			t.Fatalf("bad wire accepted: %v", err)
		}
		if err := NewProfileStrictCodec().Unmarshal(wire, &pb.BeginOwnCampusCertificationRequest{}); err != nil {
			t.Fatal("strict codec should mark rejected payload", err)
		}
	}
	if err := campusCertificationWire(valid, &pb.GetOwnCampusCertificationRequest{}); err == nil {
		t.Fatal("Get accepted input fields")
	}
}
func TestCampusExactMethodsAndErrorTable(t *testing.T) {
	for _, method := range []string{pb.CampusCertificationService_BeginOwnCampusCertification_FullMethodName, pb.CampusCertificationService_CompleteOwnCampusCertification_FullMethodName, pb.CampusCertificationService_GetOwnCampusCertification_FullMethodName} {
		if !campusCertificationMethod(method) {
			t.Fatal(method)
		}
	}
	if campusCertificationMethod("/auth_center.v1.campus_certification.CampusCertificationService/FutureMethod") {
		t.Fatal("wildcard method admitted")
	}
	for _, entry := range []struct {
		err  error
		code codes.Code
	}{{d.ErrInvalid, codes.InvalidArgument}, {d.ErrSession, codes.Unauthenticated}, {d.ErrVerification, codes.InvalidArgument}, {d.ErrConflict, codes.AlreadyExists}, {d.ErrCertified, codes.AlreadyExists}, {d.ErrUnavailable, codes.Unavailable}, {d.ErrDelivery, codes.Unavailable}} {
		if got := status.Code(campusCertificationError(entry.err)); got != entry.code {
			t.Fatalf("%v: %v", entry.err, got)
		}
	}
}
