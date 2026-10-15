package transport

import (
	academicyearpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/academic_year_policy"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	academicyear "iwut-auth-center/internal/academicyear/domain"
	"iwut-auth-center/internal/profile/domain"
	"unicode/utf8"
)

type profileStrictCodec struct {
	encoding.Codec
	maxAuthentication int
}

// NewProfileStrictCodec preserves oneof presence validation before Proto discards
// earlier wire branches. Install using grpc.ForceServerCodec alongside MaxRecvMsgSize.
func NewProfileStrictCodec(limits ...int) encoding.Codec {
	n := 16 * 1024
	if len(limits) > 0 && limits[0] > 0 {
		n = limits[0]
	}
	return profileStrictCodec{encoding.GetCodec("proto"), n}
}
func (c profileStrictCodec) Unmarshal(data []byte, v any) error {
	if !passwordWire(data, v) {
		return markAuthenticationWireRejected(v, len(data) > 16384)
	}
	if !credentialManagementWire(data, v) {
		return markAuthenticationWireRejected(v, len(data) > 16384)
	}
	if !dangerProofWire(data, v) {
		return markAuthenticationWireRejected(v, false)
	}
	if err := campusCertificationWire(data, v); err != nil {
		return markAuthenticationWireRejected(v, len(data) > 16*1024)
	}
	if err := academicYearPolicyWire(data, v); err != nil {
		message := v.(proto.Message)
		proto.Reset(message)
		message.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 127, protowire.VarintType), 1))
		return nil
	}
	if err := applicationOperationsPermissionWire(data, v); err != nil {
		message := v.(proto.Message)
		proto.Reset(message)
		message.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 127, protowire.VarintType), 1))
		return nil
	}
	if err := applicationUserStorageWire(data, v); err != nil {
		message := v.(proto.Message)
		proto.Reset(message)
		message.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 127, protowire.VarintType), 1))
		return nil
	}
	if err := sessionManagementWire(data, v); err != nil {
		// grpc-go maps codec errors to INTERNAL. Preserve rejection as an
		// unknown-field marker so the handler applies admission, no-store and
		// the contracted INVALID_ARGUMENT response. Never decode rejected data.
		message := v.(proto.Message)
		proto.Reset(message)
		message.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 127, protowire.VarintType), 1))
		return nil
	}
	if err := accountClosureWire(data, v); err != nil {
		return err
	}
	if e := withdrawalWire(data, v); e != nil {
		return e
	}
	if e := emailLoginWire(data, v, c.maxAuthentication); e != nil {
		return e
	}
	if e := emailWire(data, v); e != nil {
		return markAuthenticationWireRejected(v, len(data) > 16*1024)
	}
	switch v.(type) {
	case *pb.EditOwnProfileRequest, *pb.GetOwnProfileRequest, *pb.GetProfileEditingSchemaRequest:
		if len(data) > domain.MaxMessageBytes {
			return profileError(domain.ErrLimit)
		}
	}
	if _, ok := v.(*pb.EditOwnProfileRequest); ok {
		if e := validateProfileWire(data, 0); e != nil {
			return profileError(e)
		}
	}
	return c.Codec.Unmarshal(data, v)
}

// grpc-go wraps codec errors as INTERNAL. Handlers instead receive a bounded
// rejection marker so malformed input retains its contracted admission error.
// An oversized marker preserves RESOURCE_EXHAUSTED without decoding the input.
func markAuthenticationWireRejected(v any, oversized bool) error {
	message := v.(proto.Message)
	proto.Reset(message)
	marker := protowire.AppendVarint(protowire.AppendTag(nil, 127, protowire.VarintType), 1)
	if oversized {
		marker = protowire.AppendBytes(protowire.AppendTag(nil, 127, protowire.BytesType), make([]byte, 16*1024+1))
	}
	message.ProtoReflect().SetUnknown(marker)
	return nil
}

func academicYearPolicyWire(data []byte, value any) error {
	switch value.(type) {
	case *academicyearpb.GetAcademicYearScheduleRequest:
		if len(data) != 0 {
			return academicyear.ErrInvalid
		}
		return nil
	case *academicyearpb.UpdateNextAcademicYearRolloverRequest:
		if len(data) > 16*1024 {
			return academicyear.ErrInvalid
		}
	default:
		return nil
	}
	seen := map[protowire.Number]bool{}
	for len(data) > 0 {
		number, wireType, tagSize := protowire.ConsumeTag(data)
		if tagSize < 0 || number < 1 || number > 3 || seen[number] {
			return academicyear.ErrInvalid
		}
		seen[number] = true
		data = data[tagSize:]
		fieldSize := protowire.ConsumeFieldValue(number, wireType, data)
		if fieldSize < 0 {
			return academicyear.ErrInvalid
		}
		expectedType := protowire.BytesType
		if number == 2 {
			expectedType = protowire.VarintType
		}
		if wireType != expectedType {
			return academicyear.ErrInvalid
		}
		if number == 1 || number == 3 {
			value, consumed := protowire.ConsumeBytes(data)
			if consumed < 0 || number == 1 && validateTimestampWire(value) != nil || number == 3 && !utf8.Valid(value) {
				return academicyear.ErrInvalid
			}
		}
		data = data[fieldSize:]
	}
	return nil
}

func validateTimestampWire(data []byte) error {
	seen := map[protowire.Number]bool{}
	for len(data) > 0 {
		number, wireType, tagSize := protowire.ConsumeTag(data)
		if tagSize < 0 || number < 1 || number > 2 || seen[number] || wireType != protowire.VarintType {
			return academicyear.ErrInvalid
		}
		seen[number] = true
		data = data[tagSize:]
		fieldSize := protowire.ConsumeFieldValue(number, wireType, data)
		if fieldSize < 0 {
			return academicyear.ErrInvalid
		}
		data = data[fieldSize:]
	}
	return nil
}
func validateProfileWire(data []byte, depth int) error {
	branches := 0
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return domain.ErrInvalidEdit
		}
		data = data[n:]
		size := protowire.ConsumeFieldValue(number, typ, data)
		if size < 0 {
			return domain.ErrInvalidEdit
		}
		if (depth == 2 && number >= 1 && number <= 6) || (depth == 1 && number == 2) {
			branches++
			if branches > 1 {
				return domain.ErrInvalidEdit
			}
		}
		if depth < 2 && number == 2 {
			if typ != protowire.BytesType {
				return domain.ErrInvalidEdit
			}
			nested, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return domain.ErrInvalidEdit
			}
			if e := validateProfileWire(nested, depth+1); e != nil {
				return e
			}
		}
		data = data[size:]
	}
	return nil
}
