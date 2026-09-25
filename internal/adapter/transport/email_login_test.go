package transport

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_login"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"testing"
)

func TestEmailLoginExactMethodsAndStrictWire(t *testing.T) {
	for _, method := range []string{pb.EmailLoginService_BeginEmailLogin_FullMethodName, pb.EmailLoginService_CompleteEmailLogin_FullMethodName} {
		if !emailLoginMethod(method) {
			t.Fatal("missing exact method")
		}
	}
	for _, method := range []string{"/auth_center.v1.email_login.EmailLoginService/Other", "/auth_center.v1.email_login.Other/BeginEmailLogin"} {
		if emailLoginMethod(method) {
			t.Fatal("wildcard anonymous method")
		}
	}
	field := protowire.AppendTag(nil, 1, protowire.BytesType)
	field = protowire.AppendString(field, "x")
	for _, wire := range [][]byte{append(append([]byte{}, field...), field...), protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1), protowire.AppendVarint(protowire.AppendTag(nil, 3, protowire.VarintType), 1)} {
		if e := emailLoginWire(wire, &pb.BeginEmailLoginRequest{}, 16384); e == nil {
			t.Fatal("invalid native wire accepted")
		}
	}
	if e := emailLoginWire(make([]byte, 17), &pb.BeginEmailLoginRequest{}, 16); status.Code(e) != codes.ResourceExhausted {
		t.Fatal("configured limit", e)
	}
	disabled := NewEmailLoginService(nil, 16384)
	if _, e := disabled.BeginEmailLogin(t.Context(), nil); status.Code(e) != codes.Unimplemented {
		t.Fatal("disabled method", e)
	}
}
