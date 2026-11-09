package transport

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/script_maintainer_permission"
	scriptpb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/script_permission"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"

	"iwut-auth-center/internal/scriptmaintainer/domain"
	"iwut-auth-center/internal/scriptmaintainer/usecase"
)

func scriptMaintainerPermissionMethod(operation string) bool {
	return operation == pb.ScriptMaintainerPermissionService_GetScriptMaintainerPermission_FullMethodName ||
		operation == pb.ScriptMaintainerPermissionService_ManageScriptMaintainerPermission_FullMethodName
}

func scriptMaintainerPermissionHTTPPath(path string) bool {
	return path == "/v1/script-maintainer-permissions:get" || path == "/v1/script-maintainer-permissions:manage"
}

type ScriptMaintainerPermissionService struct {
	pb.UnimplementedScriptMaintainerPermissionServiceServer
	service *usecase.Service
}

func NewScriptMaintainerPermissionService(service *usecase.Service) *ScriptMaintainerPermissionService {
	return &ScriptMaintainerPermissionService{service: service}
}

func (s *ScriptMaintainerPermissionService) GetScriptMaintainerPermission(ctx context.Context, req *pb.GetScriptMaintainerPermissionRequest) (*pb.ScriptMaintainerPermission, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || len(req.ProtoReflect().GetUnknown()) != 0 {
		return nil, scriptMaintainerPermissionError(domain.ErrInvalid)
	}
	state, err := s.service.Get(ctx, actor, req.SubjectAuthId)
	return scriptMaintainerPermissionResponse(state, err)
}

func (s *ScriptMaintainerPermissionService) ManageScriptMaintainerPermission(ctx context.Context, req *pb.ManageScriptMaintainerPermissionRequest) (*pb.ScriptMaintainerPermission, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || req.ExpectedPermissionRevision == nil || len(req.ProtoReflect().GetUnknown()) != 0 {
		return nil, scriptMaintainerPermissionError(domain.ErrInvalid)
	}
	var action string
	switch req.Action {
	case pb.ScriptMaintainerPermissionAction_SCRIPT_MAINTAINER_PERMISSION_ACTION_GRANT:
		action = "GRANT"
	case pb.ScriptMaintainerPermissionAction_SCRIPT_MAINTAINER_PERMISSION_ACTION_REVOKE:
		action = "REVOKE"
	default:
		return nil, scriptMaintainerPermissionError(domain.ErrInvalid)
	}
	state, err := s.service.Manage(ctx, domain.Command{ActorAuthID: actor, SubjectAuthID: req.SubjectAuthId, Permission: domain.MaintainPermission, Action: action, ExpectedRevision: req.GetExpectedPermissionRevision(), Reason: req.Reason})
	return scriptMaintainerPermissionResponse(state, err)
}

func scriptMaintainerPermissionResponse(state domain.State, err error) (*pb.ScriptMaintainerPermission, error) {
	if err != nil {
		return nil, scriptMaintainerPermissionError(err)
	}
	maintain := state.For(domain.MaintainPermission)
	return &pb.ScriptMaintainerPermission{SubjectAuthId: state.AuthID, Granted: maintain.Granted, Effective: maintain.Effective, PermissionRevision: state.Revision}, nil
}

func scriptMaintainerPermissionError(err error) error {
	return scriptPermissionStatus(err, true)
}

func scriptPermissionStatus(err error, legacy bool) error {
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
	if legacy {
		return transportStatus(code, reason, "script maintainer permission request failed")
	}
	return transportStatus(code, strings.Replace(reason, "SCRIPT_MAINTAINER_PERMISSION", "SCRIPT_PERMISSION", 1), "script permission request failed")
}

// Detect duplicate/unknown fields before Proto can discard them. Also reject
// enum varints that would truncate to an otherwise valid int32 permission or action.
func scriptPermissionWire(data []byte, message any) bool {
	var max protowire.Number
	var enumMax [6]uint64
	switch message.(type) {
	case *pb.GetScriptMaintainerPermissionRequest, *scriptpb.GetScriptPermissionsRequest:
		max = 1
	case *pb.ManageScriptMaintainerPermissionRequest:
		max = 4
		enumMax[2] = 2
	case *scriptpb.ManageScriptPermissionRequest:
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
			if n < 0 || (enumMax[field] != 0 && value > enumMax[field]) {
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
