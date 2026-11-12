package transport

import (
	"context"
	"errors"
	"unicode/utf8"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/script_permission"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"

	"iwut-auth-center/internal/scriptpermission/domain"
)

func scriptPermissionStatus(err error) error {
	code, reason := codes.Unavailable, domain.ErrUnavailable.Error()
	for _, mapping := range []struct {
		err  error
		code codes.Code
	}{
		{domain.ErrIdentity, codes.Unauthenticated}, {domain.ErrInvalid, codes.InvalidArgument},
		{domain.ErrForbidden, codes.PermissionDenied}, {domain.ErrSubject, codes.NotFound},
		{domain.ErrConflict, codes.Aborted}, {domain.ErrGrantBlocked, codes.FailedPrecondition},
		{domain.ErrExhausted, codes.FailedPrecondition}, {domain.ErrRate, codes.ResourceExhausted},
	} {
		if errors.Is(err, mapping.err) {
			code, reason = mapping.code, mapping.err.Error()
			break
		}
	}
	if errors.Is(err, context.Canceled) {
		code = codes.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	return transportStatus(code, reason, "script permission request failed")
}

// Detect duplicate/unknown fields before Proto can discard them. Also reject
// enum varints that would truncate to an otherwise valid int32 permission or action.
func scriptPermissionWire(data []byte, message any) bool {
	var max protowire.Number
	var enumMax [6]uint64
	switch message.(type) {
	case *pb.GetOwnScriptPermissionsRequest:
		return len(data) == 0
	case *pb.GetScriptPermissionsRequest:
		max = 1
	case *pb.ManageScriptPermissionRequest:
		max = 5
		enumMax[2], enumMax[3] = 5, 2
	default:
		return true
	}
	if len(data) > 16*1024 {
		return false
	}
	var seen [6]bool
	for len(data) != 0 {
		field, typ, n := protowire.ConsumeTag(data)
		if n < 0 || field < 1 || field > max || seen[field] {
			return false
		}
		seen[field] = true
		data = data[n:]
		if field > 1 && field < max {
			if typ != protowire.VarintType {
				return false
			}
			value, n := protowire.ConsumeVarint(data)
			if n < 0 || (enumMax[field] != 0 && value > enumMax[field]) || (field == 2 && value < 2) {
				return false
			}
			data = data[n:]
		} else {
			if typ != protowire.BytesType {
				return false
			}
			value, n := protowire.ConsumeBytes(data)
			if n < 0 || !utf8.Valid(value) {
				return false
			}
			data = data[n:]
		}
	}
	return true
}
