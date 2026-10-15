package transport

import (
	"context"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v3/email_account"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	d "iwut-auth-center/internal/emailaccount/domain"
	pwd "iwut-auth-center/internal/password/domain"
	"strings"
	"testing"
)

func TestEmailAccountExactCarrierAndMethodBoundary(t *testing.T) {
	if !emailAccountMethod(pb.EmailAccountService_GetOwnEmails_FullMethodName) || emailAccountMethod("/auth_center.v3.email_account.EmailAccountService/FutureMethod") {
		t.Fatal("method wildcard")
	}
	for _, md := range []metadata.MD{{"x-iwut-session": {""}}, {"x-iwut-session": {"bad"}}, {"cookie": {"ignored"}}, {"authorization": {"Bearer ignored"}}, {"x-iwut-identity": {"ignored"}}, {"x-iwut-service-identity": {"ignored"}}} {
		if _, err := emailAccountCarrier(metadata.NewIncomingContext(context.Background(), md), false); status.Code(err) != codes.Unauthenticated {
			t.Fatal("anonymous carrier fallback", err)
		}
	}
	if _, err := emailAccountCarrier(context.Background(), true); status.Code(err) != codes.Unauthenticated {
		t.Fatal("missing Session", err)
	}
	if _, err := emailAccountCarrier(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}
func TestEmailAccountStrictHTTPAndNativeWire(t *testing.T) {
	good := `{"requestId":"id","email":"email","expectedDirectoryRevision":"1"}`
	if err := validateEmailAccountJSON([]byte(good), &pb.BeginAddOwnEmailRequest{}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{}`, `null`, strings.Replace(good, `"1"`, `1`, 1), strings.Replace(good, `"1"`, `null`, 1), strings.Replace(good, "requestId", "request_id", 1), `{"requestId":"id","email":"email","expectedDirectoryRevision":"1","unknown":"secret"}`} {
		if err := validateEmailAccountJSON([]byte(bad), &pb.BeginAddOwnEmailRequest{}); status.Code(err) != codes.InvalidArgument {
			t.Fatal("invalid JSON accepted", bad, err)
		}
	}
	field := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "a")
	invalidUTF8 := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), []byte{255})
	for _, wire := range [][]byte{append(append([]byte{}, field...), field...), invalidUTF8, protowire.AppendVarint(protowire.AppendTag(nil, 4, protowire.VarintType), 1)} {
		request := &pb.BeginAddOwnEmailRequest{}
		if err := NewProfileStrictCodec().Unmarshal(wire, request); err != nil {
			t.Fatal("codec lost admission marker", err)
		}
		if !hasUnknown(request) {
			t.Fatal("rejected wire silently accepted")
		}
	}
	for _, entry := range []struct {
		err  error
		code codes.Code
	}{{d.ErrBindingLimit, codes.AlreadyExists}, {d.ErrLoginRemoval, codes.AlreadyExists}, {d.ErrBindingNotFound, codes.NotFound}, {d.ErrRoleConflict, codes.Aborted}, {pwd.ErrAuthentication, codes.Unauthenticated}} {
		if status.Code(emailAccountError(entry.err)) != entry.code {
			t.Fatal(entry)
		}
	}
}
