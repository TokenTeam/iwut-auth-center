package transport

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_withdrawal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestWithdrawalStrictWireAndExactDispatch(t *testing.T) {
	request := &pb.PrepareDeveloperWithdrawalRequest{RequestId: "00000000-0000-4000-8000-000000000000", ExpectedDeveloperRevision: 1}
	valid, _ := proto.Marshal(request)
	if e := withdrawalWire(valid, &pb.PrepareDeveloperWithdrawalRequest{}); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{append(append([]byte{}, valid...), valid...), append(append([]byte{}, valid...), protowire.AppendTag(nil, 3, protowire.VarintType)...), protowire.AppendTag(nil, 1, protowire.VarintType)} {
		if e := withdrawalWire(bad, &pb.PrepareDeveloperWithdrawalRequest{}); status.Code(e) != codes.InvalidArgument {
			t.Fatal(e)
		}
	}
	if !developerWithdrawalMethod(pb.DeveloperWithdrawalService_GetDeveloperWithdrawal_FullMethodName) || developerWithdrawalMethod("/auth_center.v1.developer_withdrawal.DeveloperWithdrawalService/Arbitrary") {
		t.Fatal("broad method dispatch")
	}
	permission, ok := permissionForOperation("/auth_center.v1.account_owner_exit.AccountOwnerExitDecisionService/GetAccountOwnerExitDecision")
	if !ok || permission != PermissionOwnerExitRead {
		t.Fatal(permission, ok)
	}
}
