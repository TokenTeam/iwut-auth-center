package transport

import (
	"bytes"
	"encoding/json"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	d "iwut-auth-center/internal/emailaccount/domain"
	"strings"
	"unicode/utf8"
)

func emailAccountHTTPPath(path string) bool {
	return strings.HasPrefix(path, "/v3/email-registrations") || strings.HasPrefix(path, "/v3/users/me/email") || path == "/v3/users/me/login-email:switch"
}
func emailAccountRequest(v any) (proto.Message, bool) {
	switch r := v.(type) {
	case *pb.BeginEmailRegistrationRequest:
		return r, true
	case *pb.CompleteEmailRegistrationRequest:
		return r, true
	case *pb.GetOwnEmailsRequest:
		return r, true
	case *pb.BeginAddOwnEmailRequest:
		return r, true
	case *pb.CompleteAddOwnEmailRequest:
		return r, true
	case *pb.SwitchOwnLoginEmailRequest:
		return r, true
	case *pb.RemoveOwnEmailRequest:
		return r, true
	}
	return nil, false
}
func validateEmailAccountJSON(data []byte, v any) error {
	msg, ok := emailAccountRequest(v)
	if !ok {
		return nil
	}
	if !strictAccountJSON(data, msg.ProtoReflect().Descriptor()) {
		return emailAccountError(d.ErrInvalid)
	}
	return nil
}

// ProtoJSON handles duplicate keys afterward; this pass rejects nulls, aliases,
// omitted fields and numeric int64s before they become protobuf defaults.
func strictAccountJSON(data []byte, md protoreflect.MessageDescriptor) bool {
	if !utf8.Valid(data) {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil || len(fields) != md.Fields().Len() {
		return false
	}
	for i := 0; i < md.Fields().Len(); i++ {
		fd := md.Fields().Get(i)
		raw, ok := fields[fd.JSONName()]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
		if fd.Kind() == protoreflect.MessageKind {
			if !strictAccountJSON(raw, fd.Message()) {
				return false
			}
			continue
		}
		var value string
		if json.Unmarshal(raw, &value) != nil {
			return false
		}
	}
	return true
}
