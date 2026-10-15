package transport

import (
	"bytes"
	closurepb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_closure"
	reauthpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_close_reauth"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDangerProofJSONRequiresExactPasswordField(t *testing.T) {
	for _, tc := range []struct {
		path, valid string
		newMessage  func() proto.Message
	}{
		{"/v1/account-closures:prepare", `{"operationId":"op","signature":"AQ==","currentPassword":"password"}`, func() proto.Message { return &closurepb.PrepareAccountClosureRequest{} }},
		{"/v1/application-close-reauth:complete", `{"operationId":"op","applicationId":"app","signatureDer":"AQ==","currentPassword":"password"}`, func() proto.Message { return &reauthpb.CompleteApplicationCloseReauthRequest{} }},
	} {
		for name, body := range map[string]string{
			"valid":        tc.valid,
			"omitted":      strings.Replace(tc.valid, `,"currentPassword":"password"`, "", 1),
			"null":         strings.Replace(tc.valid, `"currentPassword":"password"`, `"currentPassword":null`, 1),
			"alias":        strings.Replace(tc.valid, "currentPassword", "current_password", 1),
			"duplicate":    strings.Replace(tc.valid, `"currentPassword":"password"`, `"currentPassword":"password","currentPassword":"other"`, 1),
			"unknown":      strings.Replace(tc.valid, `"currentPassword":"password"`, `"currentPassword":"password","extra":"value"`, 1),
			"invalid utf8": strings.Replace(tc.valid, "password", string([]byte{0xff}), 1),
		} {
			t.Run(tc.path+"/"+name, func(t *testing.T) {
				req := httptest.NewRequest("POST", tc.path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				err := authHTTPDecoder(16*1024)(req, tc.newMessage())
				if (err == nil) != (name == "valid") {
					t.Fatalf("unexpected decode: %v", err)
				}
			})
		}
	}
}

func TestDangerProofNativeRejectsDuplicateUnknownInvalidUTF8(t *testing.T) {
	for _, message := range []proto.Message{&closurepb.PrepareAccountClosureRequest{OperationId: "op", Signature: []byte{1}, CurrentPassword: "password"}, &reauthpb.CompleteApplicationCloseReauthRequest{OperationId: "op", ApplicationId: "app", SignatureDer: []byte{1}, CurrentPassword: "password"}} {
		data, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		fd := message.ProtoReflect().Descriptor().Fields().ByName("current_password")
		pwd := protowire.AppendString(protowire.AppendTag(nil, protowire.Number(fd.Number()), protowire.BytesType), "other")
		unknown := protowire.AppendString(protowire.AppendTag(nil, 99, protowire.BytesType), "extra")
		invalid := protowire.AppendBytes(protowire.AppendTag(nil, protowire.Number(fd.Number()), protowire.BytesType), []byte{0xff})
		for name, wire := range map[string][]byte{"duplicate": append(bytes.Clone(data), pwd...), "unknown": append(bytes.Clone(data), unknown...), "utf8": invalid, "oversized": make([]byte, 16385)} {
			t.Run(string(message.ProtoReflect().Descriptor().FullName())+"/"+name, func(t *testing.T) {
				target := message.ProtoReflect().New().Interface()
				if err := NewProfileStrictCodec().Unmarshal(wire, target); err != nil || len(target.ProtoReflect().GetUnknown()) == 0 {
					t.Fatalf("not marked invalid: %v", err)
				}
			})
		}
		target := message.ProtoReflect().New().Interface()
		if err := NewProfileStrictCodec().Unmarshal(data, target); err != nil || !proto.Equal(message, target) {
			t.Fatalf("valid input rejected: %v", err)
		}
	}
}
