package transport

import (
	"context"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/script_permission"

	"iwut-auth-center/internal/scriptmaintainer/domain"
	"iwut-auth-center/internal/scriptmaintainer/usecase"
)

func scriptPermissionMethod(operation string) bool {
	return ownScriptPermissionMethod(operation) || operation == pb.ScriptPermissionService_GetScriptPermissions_FullMethodName ||
		operation == pb.ScriptPermissionService_ManageScriptPermission_FullMethodName
}

func ownScriptPermissionMethod(operation string) bool {
	return operation == pb.ScriptPermissionService_GetOwnScriptPermissions_FullMethodName
}

func scriptPermissionHTTPPath(path string) bool {
	return path == "/v1/users/me/script-permissions" || path == "/v1/script-permissions:get" || path == "/v1/script-permissions:manage"
}

var scriptPermissionIDs = [...]string{
	pb.ScriptPermission_SCRIPT_PERMISSION_MAINTAIN: domain.MaintainPermission,
	pb.ScriptPermission_SCRIPT_PERMISSION_REVIEW:   domain.ReviewPermission,
	pb.ScriptPermission_SCRIPT_PERMISSION_PUBLISH:  domain.PublishPermission,
	pb.ScriptPermission_SCRIPT_PERMISSION_SUSPEND:  domain.SuspendPermission,
	pb.ScriptPermission_SCRIPT_PERMISSION_RESTORE:  domain.RestorePermission,
}

type ScriptPermissionService struct {
	pb.UnimplementedScriptPermissionServiceServer
	service *usecase.Service
}

func NewScriptPermissionService(service *usecase.Service) *ScriptPermissionService {
	return &ScriptPermissionService{service: service}
}

func (s *ScriptPermissionService) GetOwnScriptPermissions(ctx context.Context, req *pb.GetOwnScriptPermissionsRequest) (*pb.ScriptPermissions, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || len(req.ProtoReflect().GetUnknown()) != 0 {
		return nil, scriptPermissionStatus(domain.ErrInvalid, false)
	}
	state, err := s.service.GetOwn(ctx, actor)
	return scriptPermissionResponse(state, err)
}

func (s *ScriptPermissionService) GetScriptPermissions(ctx context.Context, req *pb.GetScriptPermissionsRequest) (*pb.ScriptPermissions, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || len(req.ProtoReflect().GetUnknown()) != 0 {
		return nil, scriptPermissionStatus(domain.ErrInvalid, false)
	}
	state, err := s.service.Get(ctx, actor, req.SubjectAuthId)
	return scriptPermissionResponse(state, err)
}

func (s *ScriptPermissionService) ManageScriptPermission(ctx context.Context, req *pb.ManageScriptPermissionRequest) (*pb.ScriptPermissions, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil || req.ExpectedPermissionRevision == nil || len(req.ProtoReflect().GetUnknown()) != 0 ||
		req.Permission <= 0 || int(req.Permission) >= len(scriptPermissionIDs) {
		return nil, scriptPermissionStatus(domain.ErrInvalid, false)
	}
	var action string
	switch req.Action {
	case pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_GRANT:
		action = "GRANT"
	case pb.ScriptPermissionAction_SCRIPT_PERMISSION_ACTION_REVOKE:
		action = "REVOKE"
	default:
		return nil, scriptPermissionStatus(domain.ErrInvalid, false)
	}
	state, err := s.service.Manage(ctx, domain.Command{
		ActorAuthID: actor, SubjectAuthID: req.SubjectAuthId, Permission: scriptPermissionIDs[req.Permission],
		Action: action, ExpectedRevision: req.GetExpectedPermissionRevision(), Reason: req.Reason,
	})
	return scriptPermissionResponse(state, err)
}

func scriptPermissionResponse(state domain.State, err error) (*pb.ScriptPermissions, error) {
	if err != nil {
		return nil, scriptPermissionStatus(err, false)
	}
	result := &pb.ScriptPermissions{SubjectAuthId: state.AuthID, PermissionRevision: state.Revision}
	for i, id := range scriptPermissionIDs[1:] {
		permission := state.For(id)
		result.Permissions = append(result.Permissions, &pb.ScriptPermissionState{
			Permission: pb.ScriptPermission(i + 1), Granted: permission.Granted, Effective: permission.Effective,
		})
	}
	return result, nil
}
