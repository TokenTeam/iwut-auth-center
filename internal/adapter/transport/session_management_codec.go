package transport

import (
	"bytes"
	"context"
	"encoding/json"
	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/session_management"
	"google.golang.org/protobuf/encoding/protowire"
	d "iwut-auth-center/internal/sessionmanagement/domain"
	"unicode/utf8"
)

func sessionManagementWire(data []byte, v any) error {
	list := false
	switch v.(type) {
	case *pb.ListOwnSessionsRequest:
		list = true
	case *pb.RevokeOwnSessionsRequest:
	default:
		return nil
	}
	invalid := func() error { return sessionManagementError(context.Background(), d.ErrInvalidRequest) }
	if len(data) > sessionManagementLimit {
		return invalid()
	}
	seen := map[protowire.Number]bool{}
	count := 0
	for len(data) > 0 {
		n, typ, k := protowire.ConsumeTag(data)
		if k < 0 {
			return invalid()
		}
		data = data[k:]
		if list {
			if seen[n] || n < 1 || n > 2 {
				return invalid()
			}
			seen[n] = true
			if n == 1 {
				if typ != protowire.VarintType {
					return invalid()
				}
				v, k := protowire.ConsumeVarint(data)
				if k < 0 || v < 1 || v > 50 {
					return invalid()
				}
				data = data[k:]
				continue
			}
		} else {
			if n != 1 {
				return invalid()
			}
			count++
			if count > 50 {
				return invalid()
			}
		}
		if typ != protowire.BytesType {
			return invalid()
		}
		value, k := protowire.ConsumeBytes(data)
		if k < 0 || !utf8.Valid(value) {
			return invalid()
		}
		data = data[k:]
	}
	return nil
}
func validateSessionManagementJSON(data []byte, v any) error {
	switch v.(type) {
	case *pb.ListOwnSessionsRequest, *pb.RevokeOwnSessionsRequest:
	default:
		return nil
	}
	invalid := func() error { return sessionManagementError(context.Background(), d.ErrInvalidRequest) }
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return invalid()
	}
	for key, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalid()
		}
		if key == "sessionIds" || key == "session_ids" {
			var items []json.RawMessage
			if json.Unmarshal(value, &items) != nil {
				return invalid()
			}
			for _, item := range items {
				if bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
					return invalid()
				}
			}
		}
	}
	return nil
}
