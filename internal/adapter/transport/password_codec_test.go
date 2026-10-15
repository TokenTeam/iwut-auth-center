package transport

import (
	"bytes"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_management"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasswordManagementStrictMessagesAndCarriers(t *testing.T) {
	for _, tc := range []struct {
		r    proto.Message
		body string
	}{{&pb.ChangeOwnPasswordRequest{}, `{"requestId":"id","currentPassword":"secret","newPassword":"secret"}`}, {&pb.GetOwnPasswordChangeRequest{}, `{"requestId":"id"}`}, {&pb.BeginPasswordResetRequest{}, `{"requestId":"id","loginEmail":"test@example.test"}`}, {&pb.CompletePasswordResetRequest{}, `{"operationId":"id","code":"12345678","newPassword":"secret"}`}} {
		for _, body := range []string{tc.body, "null", strings.Replace(tc.body, `"id"`, `null`, 1), strings.Replace(tc.body, `"id"`, `12`, 1), strings.TrimSuffix(tc.body, "}") + `,"extra":"secret"}`, strings.TrimSuffix(tc.body, "}") + `,"requestId":"other"}`} {
			r := httptest.NewRequest("POST", "/v1/password-resets", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			err := authHTTPDecoder(16384)(r, tc.r.ProtoReflect().New().Interface())
			if (err == nil) != (body == tc.body) {
				t.Fatal(body, err)
			}
		}
		for _, raw := range [][]byte{{0x0a, 0x01, 'x', 0x0a, 0x01, 'y'}, {0xf8, 0x07, 0x01}, bytes.Repeat([]byte{1}, 16385)} {
			r := tc.r.ProtoReflect().New().Interface()
			if err := NewProfileStrictCodec().Unmarshal(raw, r); err != nil || len(r.ProtoReflect().GetUnknown()) == 0 {
				t.Fatal(err)
			}
		}
	}
	for _, md := range []metadata.MD{metadata.Pairs("x-iwut-session", ""), metadata.Pairs("authorization", ""), metadata.Pairs("cookie", ""), metadata.Pairs("x-iwut-identity", ""), metadata.Pairs("x-iwut-service-identity", "")} {
		if _, err := passwordInput(metadata.NewIncomingContext(t.Context(), md), &pb.BeginPasswordResetRequest{}, false); err == nil {
			t.Fatal("anonymous carrier accepted")
		}
	}
}
