package transport

import (
	"bytes"
	"encoding/json"
	lpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_login"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/password_management"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"unicode/utf8"
)

func passwordRequest(v any) proto.Message {
	switch r := v.(type) {
	case *lpb.BeginPasswordLoginRequest:
		return r
	case *lpb.CompletePasswordLoginRequest:
		return r
	case *pb.ChangeOwnPasswordRequest:
		return r
	case *pb.GetOwnPasswordChangeRequest:
		return r
	case *pb.BeginPasswordResetRequest:
		return r
	case *pb.CompletePasswordResetRequest:
		return r
	}
	return nil
}
func passwordWire(data []byte, v any) bool {
	r := passwordRequest(v)
	return r == nil || len(data) <= 16384 && strictEmailWire(data, r.ProtoReflect().Descriptor())
}
func passwordJSON(data []byte, v any) bool {
	r := passwordRequest(v)
	if r == nil {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	return passwordObjectJSON(data, r.ProtoReflect().Descriptor())
}
func passwordObjectJSON(data []byte, descriptor protoreflect.MessageDescriptor) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != descriptor.Fields().Len() {
		return false
	}
	for k, raw := range fields {
		fd := descriptor.Fields().ByJSONName(k)
		if fd == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
		if fd.Kind() == protoreflect.MessageKind {
			if !passwordObjectJSON(raw, fd.Message()) {
				return false
			}
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) != nil || text == "" {
			return false
		}
	}
	return true
}
