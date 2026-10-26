package transport

import (
	"context"
	"errors"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/scope_management"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"

	d "iwut-auth-center/internal/scopemanagement/domain"
	"iwut-auth-center/internal/scopemanagement/usecase"
)

const scopeManagementMessageLimit = 128 * 1024

func scopeManagementMethod(operation string) bool {
	return operation == pb.ScopeManagementService_GetManagedScopeCatalog_FullMethodName || operation == pb.ScopeManagementService_ChangeScopeCatalog_FullMethodName || operation == pb.ScopeManagementService_GetScopeCatalogOperation_FullMethodName
}

type ScopeManagementService struct {
	pb.UnimplementedScopeManagementServiceServer
	service *usecase.Service
}

func NewScopeManagementService(service *usecase.Service) *ScopeManagementService {
	return &ScopeManagementService{service: service}
}

func (s *ScopeManagementService) GetManagedScopeCatalog(ctx context.Context, req *pb.GetManagedScopeCatalogRequest) (*pb.ManagedScopeCatalog, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if !validScopeManagementMessage(req) {
		return nil, scopeManagementInputError(req)
	}
	if s.service == nil {
		return nil, scopeManagementError(d.ErrUnavailable)
	}
	snapshot, err := s.service.Get(ctx, actor)
	if err != nil {
		return nil, scopeManagementError(err)
	}
	response := &pb.ManagedScopeCatalog{Revision: snapshot.Revision, GeneratedAt: timestamppb.New(snapshot.GeneratedAt), Digest: snapshot.Digest, Scopes: make([]*pb.ScopeDefinition, 0, len(snapshot.Scopes))}
	for _, scope := range snapshot.Scopes {
		response.Scopes = append(response.Scopes, &pb.ScopeDefinition{Name: scope.Name, Label: scope.Label, Description: scope.Description, Kind: scope.Kind, Audience: scope.Audience, ProfileField: scope.ProfileField, ProfileValueType: scope.ProfileValueType, Enabled: scope.Enabled})
	}
	return response, nil
}

func (s *ScopeManagementService) ChangeScopeCatalog(ctx context.Context, req *pb.ChangeScopeCatalogRequest) (*pb.ScopeCatalogOperation, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if !validScopeManagementMessage(req) {
		return nil, scopeManagementInputError(req)
	}
	if req.ExpectedRevision == nil || len(req.Changes) == 0 || len(req.Changes) > 32 {
		return nil, scopeManagementError(d.ErrInvalid)
	}
	command := d.Command{ActorAuthID: actor, OperationID: req.OperationId, ExpectedRevision: req.GetExpectedRevision(), ExpectedDigest: req.ExpectedDigest, Reason: req.Reason, Changes: make([]d.Change, 0, len(req.Changes))}
	for _, change := range req.Changes {
		if change == nil {
			return nil, scopeManagementError(d.ErrInvalid)
		}
		switch branch := change.Change.(type) {
		case *pb.ScopeChange_Register:
			if branch.Register == nil || branch.Register.Definition == nil || branch.Register.Definition.Enabled == nil {
				return nil, scopeManagementError(d.ErrInvalid)
			}
			definition := branch.Register.Definition
			command.Changes = append(command.Changes, d.Change{Kind: "REGISTER", Definition: d.Definition{Name: definition.Name, Label: definition.Label, Description: definition.Description, Kind: definition.Kind, Audience: definition.Audience, ProfileField: definition.ProfileField, Enabled: definition.GetEnabled()}, Contract: branch.Register.Contract, ProviderEvidence: branch.Register.ProviderEvidence})
		case *pb.ScopeChange_CorrectText:
			if branch.CorrectText == nil {
				return nil, scopeManagementError(d.ErrInvalid)
			}
			command.Changes = append(command.Changes, d.Change{Kind: "CORRECT_TEXT", Name: branch.CorrectText.Name, Label: branch.CorrectText.Label, Description: branch.CorrectText.Description})
		case *pb.ScopeChange_SetEnabled:
			if branch.SetEnabled == nil || branch.SetEnabled.Enabled == nil {
				return nil, scopeManagementError(d.ErrInvalid)
			}
			command.Changes = append(command.Changes, d.Change{Kind: "SET_ENABLED", Name: branch.SetEnabled.Name, Enabled: branch.SetEnabled.GetEnabled()})
		default:
			return nil, scopeManagementError(d.ErrInvalid)
		}
	}
	if s.service == nil {
		return nil, scopeManagementError(d.ErrUnavailable)
	}
	operation, err := s.service.Change(ctx, command)
	if err != nil {
		return nil, scopeManagementError(err)
	}
	return scopeCatalogOperationResponse(operation), nil
}

func (s *ScopeManagementService) GetScopeCatalogOperation(ctx context.Context, req *pb.GetScopeCatalogOperationRequest) (*pb.ScopeCatalogOperation, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if !validScopeManagementMessage(req) {
		return nil, scopeManagementInputError(req)
	}
	if s.service == nil {
		return nil, scopeManagementError(d.ErrUnavailable)
	}
	operation, err := s.service.Operation(ctx, actor, req.OperationId)
	if err != nil {
		return nil, scopeManagementError(err)
	}
	return scopeCatalogOperationResponse(operation), nil
}

func scopeCatalogOperationResponse(operation d.Operation) *pb.ScopeCatalogOperation {
	return &pb.ScopeCatalogOperation{OperationId: operation.OperationID, RequestDigest: operation.RequestDigest, ActorAuthId: operation.ActorAuthID, Reason: operation.Reason, Outcome: operation.Outcome, BaseRevision: operation.BaseRevision, ResultRevision: operation.ResultRevision, ResultGeneratedAt: timestamppb.New(operation.ResultGeneratedAt), ResultDigest: operation.ResultDigest, OccurredAt: timestamppb.New(operation.OccurredAt)}
}

func validScopeManagementMessage(message proto.Message) bool {
	if message == nil || !message.ProtoReflect().IsValid() || proto.Size(message) > scopeManagementMessageLimit {
		return false
	}
	return scopeManagementUnknownFree(message.ProtoReflect())
}

func scopeManagementUnknownFree(message protoreflect.Message) bool {
	if !message.IsValid() || len(message.GetUnknown()) != 0 {
		return false
	}
	valid := true
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() != protoreflect.MessageKind {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if !scopeManagementUnknownFree(list.Get(i).Message()) {
					valid = false
					return false
				}
			}
		} else {
			valid = scopeManagementUnknownFree(value.Message())
		}
		return valid
	})
	return valid
}

func scopeManagementError(err error) error {
	code, reason := codes.Unavailable, d.ErrUnavailable.Error()
	for _, entry := range []struct {
		err  error
		code codes.Code
	}{{d.ErrIdentity, codes.Unauthenticated}, {d.ErrInvalid, codes.InvalidArgument}, {d.ErrForbidden, codes.PermissionDenied}, {d.ErrConflict, codes.Aborted}, {d.ErrOperationConflict, codes.Aborted}, {d.ErrNotFound, codes.NotFound}, {d.ErrBlocked, codes.FailedPrecondition}, {d.ErrRevisionExhausted, codes.FailedPrecondition}, {d.ErrRate, codes.ResourceExhausted}} {
		if errors.Is(err, entry.err) {
			code, reason = entry.code, entry.err.Error()
			break
		}
	}
	// A timeout can hide a committed transaction. Preserve the contracted
	// unavailable result and recover using the same operation identifier.
	return transportStatus(code, reason, "scope management request failed")
}
