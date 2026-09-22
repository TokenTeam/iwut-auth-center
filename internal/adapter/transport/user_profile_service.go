package transport

import (
	"context"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
	pb "iwut-auth-center/api/gen/go/auth_center/v1/user_profile"
	"iwut-auth-center/internal/profile/domain"
	"iwut-auth-center/internal/profile/usecase"
)

type UserProfileServer struct {
	pb.UnimplementedUserProfileServiceServer
	service *usecase.Service
}

func NewUserProfileServer(s *usecase.Service) *UserProfileServer {
	return &UserProfileServer{service: s}
}
func RegisterUserProfileServer(registrar grpc.ServiceRegistrar, s *UserProfileServer) {
	pb.RegisterUserProfileServiceServer(registrar, s)
}
func (s *UserProfileServer) EditOwnProfile(ctx context.Context, r *pb.EditOwnProfileRequest) (*pb.EditOwnProfileResponse, error) {
	id, e := profileAuthID(ctx)
	if e != nil {
		return nil, e
	}
	if r == nil || r.ExpectedRevision == nil {
		return nil, profileError(domain.ErrInvalidRevision)
	}
	c := domain.Command{ExpectedRevision: r.GetExpectedRevision(), Remove: r.Remove}
	for _, a := range r.Set {
		if a == nil || a.Value == nil {
			return nil, profileError(domain.ErrInvalidEdit)
		}
		v := domain.Value{}
		switch value := a.Value.Value.(type) {
		case *pb.ProfileValue_StringValue:
			v.Type = domain.String
			v.Text = value.StringValue
		case *pb.ProfileValue_IntegerValue:
			v.Type = domain.Integer
			v.Integer = value.IntegerValue
		case *pb.ProfileValue_BooleanValue:
			v.Type = domain.Boolean
			v.Boolean = value.BooleanValue
		case *pb.ProfileValue_DateValue:
			v.Type = domain.Date
			v.Text = value.DateValue
		default:
			return nil, profileError(domain.ErrInvalidEdit)
		}
		c.Set = append(c.Set, domain.Entry{Key: a.Key, Value: v})
	}
	result, e := s.service.EditOwnProfile(ctx, id, c)
	if e != nil {
		return nil, profileError(e)
	}
	return &pb.EditOwnProfileResponse{Changed: result.Changed, Profile: profileSnapshot(result.Profile)}, nil
}
func (s *UserProfileServer) GetOwnProfile(ctx context.Context, _ *pb.GetOwnProfileRequest) (*pb.OwnUserProfileSnapshot, error) {
	id, e := profileAuthID(ctx)
	if e != nil {
		return nil, e
	}
	result, e := s.service.GetOwnProfile(ctx, id)
	if e != nil {
		return nil, profileError(e)
	}
	return profileSnapshot(result), nil
}
func (s *UserProfileServer) GetProfileEditingSchema(ctx context.Context, _ *pb.GetProfileEditingSchemaRequest) (*pb.ProfileEditingSchema, error) {
	id, e := profileAuthID(ctx)
	if e != nil {
		return nil, e
	}
	defs, e := s.service.GetProfileEditingSchema(ctx, id)
	if e != nil {
		return nil, profileError(e)
	}
	result := &pb.ProfileEditingSchema{Definitions: make([]*pb.ProfileFieldDefinition, 0, len(defs)), Limits: &pb.ProfileEditingLimits{MaxOperations: domain.MaxOperations, MaxFields: domain.MaxFields, MaxProfileBytes: domain.MaxProfileBytes, MaxCommandBytes: domain.MaxCommandBytes, MaxMessageBytes: domain.MaxMessageBytes}}
	for _, d := range defs {
		result.Definitions = append(result.Definitions, &pb.ProfileFieldDefinition{Key: d.Key, Label: d.Label, Description: d.Description, ValueType: string(d.ValueType), Constraints: &pb.ProfileFieldConstraints{MinLength: d.Constraints.MinLength, MaxLength: d.Constraints.MaxLength, Minimum: d.Constraints.Minimum, Maximum: d.Constraints.Maximum}})
	}
	return result, nil
}
func profileSnapshot(s domain.Snapshot) *pb.OwnUserProfileSnapshot {
	result := &pb.OwnUserProfileSnapshot{Revision: s.Revision, UpdatedAt: timestamppb.New(s.UpdatedAt), Entries: make([]*pb.ProfileFieldAssignment, 0, len(s.Entries))}
	for _, a := range s.Entries {
		v := &pb.ProfileValue{}
		switch a.Value.Type {
		case domain.String:
			v.Value = &pb.ProfileValue_StringValue{StringValue: a.Value.Text}
		case domain.Integer:
			v.Value = &pb.ProfileValue_IntegerValue{IntegerValue: a.Value.Integer}
		case domain.Boolean:
			v.Value = &pb.ProfileValue_BooleanValue{BooleanValue: a.Value.Boolean}
		case domain.Date:
			v.Value = &pb.ProfileValue_DateValue{DateValue: a.Value.Text}
		}
		result.Entries = append(result.Entries, &pb.ProfileFieldAssignment{Key: a.Key, Value: v})
	}
	return result
}
func profileError(e error) error {
	code := codes.Internal
	reason := "INTERNAL_ERROR"
	switch {
	case errors.Is(e, domain.ErrInvalidRevision), errors.Is(e, domain.ErrInvalidEdit), errors.Is(e, domain.ErrNotDefined), errors.Is(e, domain.ErrInvalidValue):
		code = codes.InvalidArgument
	case errors.Is(e, domain.ErrDenied), errors.Is(e, domain.ErrDisabled):
		code = codes.PermissionDenied
	case errors.Is(e, domain.ErrNotFound):
		code = codes.NotFound
	case errors.Is(e, domain.ErrLimit):
		code = codes.ResourceExhausted
	case errors.Is(e, domain.ErrConflict):
		code = codes.Aborted
	case errors.Is(e, domain.ErrExhausted):
		code = codes.FailedPrecondition
	case errors.Is(e, domain.ErrCatalog), errors.Is(e, domain.ErrUnavailable):
		code = codes.Unavailable
	}
	if code != codes.Internal {
		reason = e.Error()
	}
	return transportStatus(code, reason, "user profile operation failed")
}
