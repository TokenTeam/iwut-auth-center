package transport

import (
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	"iwut-auth-center/internal/profile/domain"
	"testing"
)

func TestProfileCodecBoundsBeforeDecode(t *testing.T) {
	// The listener can admit larger authentication messages when configured;
	// profile decoding must still enforce its own independent fixed ceiling.
	codec := NewProfileStrictCodec()
	for _, message := range []any{&pb.EditOwnProfileRequest{}, &pb.GetOwnProfileRequest{}, &pb.GetProfileEditingSchemaRequest{}} {
		if err := codec.Unmarshal(make([]byte, domain.MaxMessageBytes+1), message); err == nil {
			t.Fatalf("accepted oversized %T", message)
		}
	}
}
