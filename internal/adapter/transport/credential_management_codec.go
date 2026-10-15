package transport

import (
	"bytes"
	"context"
	"encoding/json"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/credential_management"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	d "iwut-auth-center/internal/credentialmanagement/domain"
	"strconv"
	"unicode/utf8"
)

func credentialManagementRequest(value any) proto.Message {
	switch r := value.(type) {
	case *pb.ListOwnCredentialsRequest:
		return r
	case *pb.SetOwnCredentialLabelRequest:
		return r
	case *pb.BeginOtherCredentialRevocationRequest:
		return r
	case *pb.CompleteOtherCredentialRevocationRequest:
		return r
	}
	return nil
}
func credentialManagementWire(data []byte, value any) bool {
	msg := credentialManagementRequest(value)
	return msg == nil || len(data) <= 16384 && strictEmailWire(data, msg.ProtoReflect().Descriptor())
}
func validateCredentialManagementJSON(data []byte, value any) error {
	msg := credentialManagementRequest(value)
	if msg == nil {
		return nil
	}
	invalid := func() error { return credentialManagementError(context.Background(), d.ErrInvalid) }
	if !utf8.Valid(data) {
		return invalid()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return invalid()
	}
	_, list := value.(*pb.ListOwnCredentialsRequest)
	md := msg.ProtoReflect().Descriptor()
	if !list && len(fields) != md.Fields().Len() {
		return invalid()
	}
	for key, raw := range fields {
		fd := md.Fields().ByJSONName(key)
		if fd == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return invalid()
		}
		if fd.Kind() == protoreflect.Uint32Kind {
			var size uint32
			if json.Unmarshal(raw, &size) != nil || size < 1 || size > 50 {
				return invalid()
			}
		} else {
			var text string
			if json.Unmarshal(raw, &text) != nil {
				return invalid()
			}
			if fd.Kind() == protoreflect.Int64Kind {
				number, err := strconv.ParseInt(text, 10, 64)
				if err != nil || number < 0 || strconv.FormatInt(number, 10) != text {
					return invalid()
				}
			}
		}
	}
	return nil
}
