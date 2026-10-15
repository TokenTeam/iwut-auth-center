package transport

import (
	"testing"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_user_storage"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestApplicationUserStorageStrictWire(t *testing.T) {
	field := func(value string) []byte {
		return protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), value)
	}
	if applicationUserStorageWire(field("application"), &pb.ClearOwnApplicationUserStorageRequest{}) != nil {
		t.Fatal("valid request rejected")
	}
	if applicationUserStorageWire(append(field("one"), field("two")...), &pb.ClearOwnApplicationUserStorageRequest{}) == nil {
		t.Fatal("duplicate application_id accepted")
	}
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 2, protowire.VarintType), 1)
	if applicationUserStorageWire(unknown, &pb.ClearOwnApplicationUserStorageRequest{}) == nil {
		t.Fatal("unknown field accepted")
	}
}
