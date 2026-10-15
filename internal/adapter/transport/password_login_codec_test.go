package transport

import (
	"bytes"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_login"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasswordLoginStrictMessagesAndCarriers(t *testing.T) {
	for _, tc := range []struct {
		r          proto.Message
		path, body string
	}{
		{&pb.BeginPasswordLoginRequest{}, "/v1/password-logins", `{"requestId":"id","loginEmail":"a@example.test","credentialProposal":{"protocolVersion":"iwut-device-v1","publicKey":"AQ=="}}`},
		{&pb.CompletePasswordLoginRequest{}, "/v1/password-logins:complete", `{"operationId":"id","password":"secret","proof":{"signature":"AQ=="}}`},
	} {
		for _, body := range []string{tc.body, "null", strings.Replace(tc.body, `"id"`, `null`, 1), strings.Replace(tc.body, `"id"`, `12`, 1), strings.TrimSuffix(tc.body, "}") + `,"requestId":"duplicate"}`, strings.Replace(tc.body, `"id"`, `"id","operation_id":"alias"`, 1), strings.Replace(tc.body, `"AQ=="`, `null`, 1), strings.Replace(tc.body, `"AQ=="`, `"AQ==","extra":"secret"`, 1)} {
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			if err := authHTTPDecoder(16384)(r, tc.r.ProtoReflect().New().Interface()); (err == nil) != (body == tc.body) {
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
	for _, md := range []metadata.MD{metadata.Pairs("x-iwut-session", ""), metadata.Pairs("authorization", ""), metadata.Pairs("cookie", ""), metadata.Pairs("x-iwut-identity", "")} {
		if _, err := passwordInput(metadata.NewIncomingContext(t.Context(), md), &pb.BeginPasswordLoginRequest{}, false); err == nil {
			t.Fatal("anonymous carrier accepted")
		}
	}
}
