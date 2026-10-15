package transport

import (
	"context"
	closurepb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/account_closure"
	reauthpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/application_close_reauth"
	"google.golang.org/protobuf/proto"
	closure "iwut-auth-center/internal/accountclosure/domain"
	reauth "iwut-auth-center/internal/applicationclosereauth/domain"
)

func dangerProofRequest(v any) proto.Message {
	switch r := v.(type) {
	case *closurepb.PrepareAccountClosureRequest:
		return r
	case *reauthpb.CompleteApplicationCloseReauthRequest:
		return r
	default:
		return nil
	}
}

// Password-bearing commands use exact lowerCamel JSON fields, no null/aliases,
// and strict wire parsing before the ordinary decoder can discard duplicates.
func dangerProofJSON(data []byte, v any) bool {
	msg := dangerProofRequest(v)
	return msg == nil || strictAccountJSON(data, msg.ProtoReflect().Descriptor())
}
func dangerProofWire(data []byte, v any) bool {
	msg := dangerProofRequest(v)
	return msg == nil || len(data) <= 16*1024 && strictEmailWire(data, msg.ProtoReflect().Descriptor())
}
func invalidDangerProofInput(v any) error {
	if _, ok := v.(*closurepb.PrepareAccountClosureRequest); ok {
		return closureError(closure.ErrInvalid)
	}
	return closeReauthError(context.Background(), reauth.ErrInvalid)
}
