package transport

import (
	"google.golang.org/grpc/encoding"
	"google.golang.org/protobuf/encoding/protowire"
	pb "iwut-auth-center/api/gen/go/auth_center/v1/user_profile"
	"iwut-auth-center/internal/profile/domain"
)

type profileStrictCodec struct{ encoding.Codec }

// NewProfileStrictCodec preserves oneof presence validation before Proto discards
// earlier wire branches. Install using grpc.ForceServerCodec alongside MaxRecvMsgSize.
func NewProfileStrictCodec() encoding.Codec { return profileStrictCodec{encoding.GetCodec("proto")} }
func (c profileStrictCodec) Unmarshal(data []byte, v any) error {
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
		if (depth == 2 && number >= 1 && number <= 4) || (depth == 1 && number == 2) {
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
