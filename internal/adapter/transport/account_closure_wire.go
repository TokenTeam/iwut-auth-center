package transport

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_closure"
	"google.golang.org/protobuf/encoding/protowire"
	d "iwut-auth-center/internal/accountclosure/domain"
)

func accountClosureWire(data []byte, value any) error {
	maxField := protowire.Number(0)
	begin := false
	switch value.(type) {
	case *pb.BeginAccountClosureRequest:
		maxField = 3
		begin = true
	case *pb.PrepareAccountClosureRequest:
		maxField = 2
	case *pb.ConfirmAccountClosureRequest:
		maxField = 3
	case *pb.CancelAccountClosureRequest, *pb.GetAccountClosureRequest:
		maxField = 1
	default:
		return nil
	}
	if len(data) > closureMessageLimit {
		return closureError(d.ErrInvalid)
	}
	seen := map[protowire.Number]bool{}
	for len(data) > 0 {
		number, kind, n := protowire.ConsumeTag(data)
		if n < 0 || number < 1 || number > maxField || kind != protowire.BytesType || seen[number] {
			return closureError(d.ErrInvalid)
		}
		if begin && (number == 2 && seen[3] || number == 3 && seen[2]) {
			return closureError(d.ErrInvalid)
		}
		seen[number] = true
		data = data[n:]
		_, n = protowire.ConsumeBytes(data)
		if n < 0 {
			return closureError(d.ErrInvalid)
		}
		data = data[n:]
	}
	return nil
}
