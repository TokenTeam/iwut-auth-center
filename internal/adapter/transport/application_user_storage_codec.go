package transport

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_user_storage"
	"google.golang.org/protobuf/encoding/protowire"
	"unicode/utf8"

	d "iwut-auth-center/internal/applicationuserstorage/domain"
)

func applicationUserStorageWire(data []byte, message any) error {
	if _, ok := message.(*pb.ClearOwnApplicationUserStorageRequest); !ok {
		return nil
	}
	invalid := func() error { return applicationUserStorageError(d.ErrInvalid) }
	if len(data) > 16*1024 {
		return invalid()
	}
	seen := false
	for len(data) > 0 {
		number, wireType, tagLength := protowire.ConsumeTag(data)
		if tagLength < 0 || number != 1 || wireType != protowire.BytesType || seen {
			return invalid()
		}
		seen = true
		data = data[tagLength:]
		value, valueLength := protowire.ConsumeBytes(data)
		if valueLength < 0 || !utf8.Valid(value) {
			return invalid()
		}
		data = data[valueLength:]
	}
	return nil
}
