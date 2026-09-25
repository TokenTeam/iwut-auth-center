package transport

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_binding"
	loginpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/email_login"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	d "iwut-auth-center/internal/emailbinding/domain"
	login "iwut-auth-center/internal/emaillogin/domain"
)

func emailWire(data []byte, v any) error {
	var msg proto.Message
	switch p := v.(type) {
	case *pb.BeginSetEmailRequest:
		msg = p
	case *pb.CompleteSetEmailRequest:
		msg = p
	case *pb.GetOwnEmailBindingRequest:
		msg = p
	default:
		return nil
	}
	if len(data) > 16*1024 {
		return transportStatus(codes.ResourceExhausted, "EMAIL_REQUEST_TOO_LARGE", "request is too large")
	}
	if !strictEmailWire(data, msg.ProtoReflect().Descriptor()) {
		return emailError(d.ErrInvalid)
	}
	return nil
}

// Reject duplicate/unknown fields and oneof conflicts before protobuf discards them.
func strictEmailWire(data []byte, md protoreflect.MessageDescriptor) bool {
	seen := map[protowire.Number]bool{}
	oneof := map[protoreflect.Name]bool{}
	for len(data) > 0 {
		n, typ, k := protowire.ConsumeTag(data)
		if k < 0 || seen[n] {
			return false
		}
		seen[n] = true
		fd := md.Fields().ByNumber(protoreflect.FieldNumber(n))
		if fd == nil {
			return false
		}
		if o := fd.ContainingOneof(); o != nil {
			if oneof[o.Name()] {
				return false
			}
			oneof[o.Name()] = true
		}
		data = data[k:]
		size := protowire.ConsumeFieldValue(n, typ, data)
		if size < 0 {
			return false
		}
		switch fd.Kind() {
		case protoreflect.MessageKind:
			if typ != protowire.BytesType {
				return false
			}
			body, k := protowire.ConsumeBytes(data)
			if k < 0 || !strictEmailWire(body, fd.Message()) {
				return false
			}
		case protoreflect.StringKind, protoreflect.BytesKind:
			if typ != protowire.BytesType {
				return false
			}
		case protoreflect.Int64Kind:
			if typ != protowire.VarintType {
				return false
			}
		default:
			return false
		}
		data = data[size:]
	}
	return true
}

func emailLoginWire(data []byte, v any, limit int) error {
	var msg proto.Message
	switch x := v.(type) {
	case *loginpb.BeginEmailLoginRequest:
		msg = x
	case *loginpb.CompleteEmailLoginRequest:
		msg = x
	default:
		return nil
	}
	if len(data) > limit {
		return transportStatus(codes.ResourceExhausted, "EMAIL_LOGIN_REQUEST_TOO_LARGE", "request is too large")
	}
	if !strictEmailWire(data, msg.ProtoReflect().Descriptor()) {
		return emailLoginError(login.ErrInvalid)
	}
	return nil
}
