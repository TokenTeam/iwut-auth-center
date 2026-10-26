package transport

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/scope_management"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	d "iwut-auth-center/internal/scopemanagement/domain"
)

func scopeManagementRequest(value any) proto.Message {
	switch request := value.(type) {
	case *pb.GetManagedScopeCatalogRequest:
		return request
	case *pb.ChangeScopeCatalogRequest:
		return request
	case *pb.GetScopeCatalogOperationRequest:
		return request
	}
	return nil
}

func validateScopeManagementJSON(data []byte, value any) error {
	if scopeManagementRequest(value) == nil {
		return nil
	}
	if !utf8.Valid(data) {
		return scopeManagementError(d.ErrInvalid)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return scopeManagementError(d.ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil || token == nil {
			return scopeManagementError(d.ErrInvalid)
		}
	}
}

func scopeManagementWire(data []byte, value any) bool {
	message := scopeManagementRequest(value)
	return message == nil || len(data) <= scopeManagementMessageLimit && strictScopeManagementWire(data, message.ProtoReflect().Descriptor())
}

func strictScopeManagementWire(data []byte, descriptor protoreflect.MessageDescriptor) bool {
	seen := map[protowire.Number]bool{}
	oneofs := map[protoreflect.Name]bool{}
	for len(data) > 0 {
		number, wireType, tagSize := protowire.ConsumeTag(data)
		if tagSize < 0 {
			return false
		}
		field := descriptor.Fields().ByNumber(protoreflect.FieldNumber(number))
		if field == nil || seen[number] && !field.IsList() {
			return false
		}
		seen[number] = true
		if oneof := field.ContainingOneof(); oneof != nil {
			if oneofs[oneof.Name()] {
				return false
			}
			oneofs[oneof.Name()] = true
		}
		data = data[tagSize:]
		size := protowire.ConsumeFieldValue(number, wireType, data)
		if size < 0 {
			return false
		}
		switch field.Kind() {
		case protoreflect.MessageKind, protoreflect.StringKind:
			if wireType != protowire.BytesType {
				return false
			}
			body, consumed := protowire.ConsumeBytes(data)
			if consumed < 0 {
				return false
			}
			if field.Kind() == protoreflect.MessageKind && !strictScopeManagementWire(body, field.Message()) || field.Kind() == protoreflect.StringKind && !utf8.Valid(body) {
				return false
			}
		case protoreflect.Int64Kind, protoreflect.BoolKind:
			if wireType != protowire.VarintType {
				return false
			}
			value, consumed := protowire.ConsumeVarint(data)
			if consumed < 0 || field.Kind() == protoreflect.BoolKind && value > 1 {
				return false
			}
		default:
			return false
		}
		data = data[size:]
	}
	return true
}

func markScopeManagementWireRejected(value any, oversized bool) error {
	message := value.(proto.Message)
	proto.Reset(message)
	marker := protowire.AppendVarint(protowire.AppendTag(nil, 127, protowire.VarintType), 1)
	if oversized {
		marker = protowire.AppendBytes(protowire.AppendTag(nil, 127, protowire.BytesType), make([]byte, scopeManagementMessageLimit+1))
	}
	message.ProtoReflect().SetUnknown(marker)
	return nil
}

func scopeManagementInputError(message proto.Message) error {
	if message != nil && proto.Size(message) > scopeManagementMessageLimit {
		return transportStatus(codes.ResourceExhausted, "SCOPE_MANAGEMENT_REQUEST_TOO_LARGE", "scope management request is too large")
	}
	return scopeManagementError(d.ErrInvalid)
}
