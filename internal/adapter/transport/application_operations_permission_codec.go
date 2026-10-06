package transport

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_operations_permission"
	"google.golang.org/protobuf/encoding/protowire"
	"unicode/utf8"
)

func applicationOperationsPermissionWire(data []byte, message any) error {
	maximumField := protowire.Number(0)
	switch message.(type) {
	case *pb.ManageApplicationOperationsPermissionRequest:
		maximumField = 5
	case *pb.GetApplicationOperationsPermissionsRequest:
		maximumField = 1
	default:
		return nil
	}
	invalid := func() error { return applicationOperationsPermissionError(nil) }
	if len(data) > 16*1024 {
		return invalid()
	}
	seen := map[protowire.Number]bool{}
	for len(data) > 0 {
		number, wireType, tagLength := protowire.ConsumeTag(data)
		if tagLength < 0 || number < 1 || number > maximumField || seen[number] {
			return invalid()
		}
		seen[number] = true
		data = data[tagLength:]
		if maximumField == 5 && (number == 3 || number == 4) {
			if wireType != protowire.VarintType {
				return invalid()
			}
			_, valueLength := protowire.ConsumeVarint(data)
			if valueLength < 0 {
				return invalid()
			}
			data = data[valueLength:]
			continue
		}
		if wireType != protowire.BytesType {
			return invalid()
		}
		value, valueLength := protowire.ConsumeBytes(data)
		if valueLength < 0 || !utf8.Valid(value) {
			return invalid()
		}
		data = data[valueLength:]
	}
	return nil
}
