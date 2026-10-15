package transport

import (
	"bytes"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/credential_management"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCredentialManagementStrictJSON(t *testing.T) {
	for _, tc := range []struct {
		msg   proto.Message
		valid string
	}{
		{&pb.ListOwnCredentialsRequest{}, `{}`},
		{&pb.SetOwnCredentialLabelRequest{}, `{"credentialId":"id","label":"","expectedLabelRevision":"0"}`},
		{&pb.BeginOtherCredentialRevocationRequest{}, `{"requestId":"id","targetCredentialId":"target"}`},
		{&pb.CompleteOtherCredentialRevocationRequest{}, `{"operationId":"id","signatureDer":"AQ==","currentPassword":"password"}`},
	} {
		for name, body := range map[string]string{"valid": tc.valid, "unknown": strings.TrimSuffix(tc.valid, "}") + `,"extra":"value"}`, "null": `null`, "alias": strings.Replace(tc.valid, "credentialId", "credential_id", 1)} {
			if name == "unknown" && tc.valid == `{}` {
				body = `{"extra":"value"}`
			}
			if name == "alias" && body == tc.valid {
				continue
			}
			req := httptest.NewRequest("POST", "/v1/users/me/credentials:list", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			target := tc.msg.ProtoReflect().New().Interface()
			err := authHTTPDecoder(16384)(req, target)
			if (err == nil) != (name == "valid") {
				t.Fatal(name, err)
			}
		}
	}
	for _, body := range []string{`{"credentialId":"id","label":null,"expectedLabelRevision":"0"}`, `{"credentialId":"id","label":"","expectedLabelRevision":0}`, `{"credentialId":"id","expectedLabelRevision":"0"}`, `{"credentialId":"id","label":"","label":"other","expectedLabelRevision":"0"}`} {
		req := httptest.NewRequest("POST", "/v1/users/me/credentials:set-label", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if err := authHTTPDecoder(16384)(req, &pb.SetOwnCredentialLabelRequest{}); err == nil {
			t.Fatal("bad label JSON accepted")
		}
	}
}
func TestCredentialManagementStrictWire(t *testing.T) {
	messages := []proto.Message{&pb.ListOwnCredentialsRequest{}, &pb.SetOwnCredentialLabelRequest{}, &pb.BeginOtherCredentialRevocationRequest{}, &pb.CompleteOtherCredentialRevocationRequest{}}
	field := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "id")
	duplicate := append(bytes.Clone(field), field...)
	unknown := protowire.AppendString(protowire.AppendTag(nil, 127, protowire.BytesType), "extra")
	badUTF8 := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte{0xff})
	for _, msg := range messages {
		for _, wire := range [][]byte{duplicate, unknown, badUTF8, make([]byte, 16385)} {
			target := msg.ProtoReflect().New().Interface()
			if err := NewProfileStrictCodec().Unmarshal(wire, target); err != nil || len(target.ProtoReflect().GetUnknown()) == 0 {
				t.Fatalf("not marked invalid %T: %v", msg, err)
			}
		}
	}
	overflow := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 1<<32+10)
	msg := &pb.ListOwnCredentialsRequest{}
	if err := NewProfileStrictCodec().Unmarshal(overflow, msg); err != nil || len(msg.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("uint32 alias accepted", err)
	}
}
