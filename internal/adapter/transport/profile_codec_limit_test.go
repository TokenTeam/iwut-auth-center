package transport

import (
	"errors"
	academicyearpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/academic_year_policy"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/user_profile"
	"google.golang.org/protobuf/encoding/protowire"
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

func TestAcademicYearPolicyCodecRejectsDuplicateUnknownAndOversizedWire(t *testing.T) {
	codec := NewProfileStrictCodec()
	revision := protowire.AppendVarint(protowire.AppendTag(nil, 2, protowire.VarintType), 1)
	duplicate := append(append([]byte(nil), revision...), revision...)
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1)
	nestedUnknown := protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1)
	nested := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), nestedUnknown)
	invalidReason := protowire.AppendBytes(protowire.AppendTag(nil, 3, protowire.BytesType), []byte{0xff})
	for name, data := range map[string][]byte{"duplicate": duplicate, "unknown": unknown, "nested unknown": nested, "invalid reason UTF-8": invalidReason, "oversized": make([]byte, 16*1024+1)} {
		message := &academicyearpb.UpdateNextAcademicYearRolloverRequest{}
		if err := codec.Unmarshal(data, message); err != nil || len(message.ProtoReflect().GetUnknown()) == 0 {
			t.Fatalf("%s was not marked invalid: err=%v unknown=%x", name, err, message.ProtoReflect().GetUnknown())
		}
	}
	get := &academicyearpb.GetAcademicYearScheduleRequest{}
	if err := codec.Unmarshal(revision, get); err != nil || len(get.ProtoReflect().GetUnknown()) == 0 {
		t.Fatalf("non-empty get was not marked invalid: %v", err)
	}
}

func TestProfileCodecRejectsMixedLegacyAndExtendedOneofBranches(t *testing.T) {
	stringValue := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "name")
	stringSet := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "NANHU")
	mixedValue := append([]byte(nil), stringValue...)
	mixedValue = protowire.AppendBytes(protowire.AppendTag(mixedValue, 5, protowire.BytesType), stringSet)
	assignment := protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), mixedValue)
	request := protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), assignment)
	if err := validateProfileWire(request, 0); !errors.Is(err, domain.ErrInvalidEdit) {
		t.Fatalf("mixed oneof branches accepted: %v", err)
	}

	extendedValue := protowire.AppendBytes(protowire.AppendTag(nil, 5, protowire.BytesType), stringSet)
	assignment = protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), extendedValue)
	request = protowire.AppendBytes(protowire.AppendTag(nil, 2, protowire.BytesType), assignment)
	if err := validateProfileWire(request, 0); err != nil {
		t.Fatalf("single extended branch rejected: %v", err)
	}
}
