package transport

import (
	"context"
	"errors"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/academic_year_policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	d "iwut-auth-center/internal/academicyear/domain"
	"iwut-auth-center/internal/academicyear/usecase"
)

func academicYearPolicyMethod(operation string) bool {
	return operation == pb.AcademicYearPolicyService_GetAcademicYearSchedule_FullMethodName || operation == pb.AcademicYearPolicyService_UpdateNextAcademicYearRollover_FullMethodName
}

type AcademicYearPolicyService struct {
	pb.UnimplementedAcademicYearPolicyServiceServer
	service *usecase.Service
}

func NewAcademicYearPolicyService(service *usecase.Service) *AcademicYearPolicyService {
	return &AcademicYearPolicyService{service: service}
}

func (service *AcademicYearPolicyService) GetAcademicYearSchedule(ctx context.Context, request *pb.GetAcademicYearScheduleRequest) (*pb.AcademicYearSchedule, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || len(request.ProtoReflect().GetUnknown()) != 0 {
		return nil, academicYearPolicyError(d.ErrInvalid)
	}
	schedule, err := service.service.Get(ctx, actor)
	if err != nil {
		return nil, academicYearPolicyError(err)
	}
	return academicYearScheduleResponse(schedule), nil
}

func (service *AcademicYearPolicyService) UpdateNextAcademicYearRollover(ctx context.Context, request *pb.UpdateNextAcademicYearRolloverRequest) (*pb.AcademicYearSchedule, error) {
	actor, err := profileAuthID(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.NextRolloverAt == nil || !request.NextRolloverAt.IsValid() || request.ExpectedRevision == nil || len(request.ProtoReflect().GetUnknown()) != 0 {
		return nil, academicYearPolicyError(d.ErrInvalid)
	}
	schedule, err := service.service.Update(ctx, d.Command{ActorAuthID: actor, NextRolloverAt: request.NextRolloverAt.AsTime(), ExpectedRevision: request.GetExpectedRevision(), Reason: request.Reason})
	if err != nil {
		return nil, academicYearPolicyError(err)
	}
	return academicYearScheduleResponse(schedule), nil
}

func academicYearScheduleResponse(schedule d.Schedule) *pb.AcademicYearSchedule {
	response := &pb.AcademicYearSchedule{CurrentAcademicYear: schedule.CurrentAcademicYear, NextRolloverAt: timestamppb.New(schedule.NextRolloverAt), ObservedAt: timestamppb.New(schedule.ObservedAt), Revision: schedule.Revision, UpdatedAt: timestamppb.New(schedule.UpdatedAt)}
	if schedule.UpdatedByAuthID != "" {
		response.UpdatedByAuthId = &schedule.UpdatedByAuthID
	}
	return response
}

func academicYearPolicyError(err error) error {
	code, reason := codes.Unavailable, d.ErrUnavailable.Error()
	for _, entry := range []struct {
		err  error
		code codes.Code
	}{{d.ErrIdentity, codes.Unauthenticated}, {d.ErrInvalid, codes.InvalidArgument}, {d.ErrForbidden, codes.PermissionDenied}, {d.ErrNotFuture, codes.FailedPrecondition}, {d.ErrConflict, codes.Aborted}, {d.ErrRevisionExhausted, codes.FailedPrecondition}, {d.ErrRangeExhausted, codes.FailedPrecondition}, {d.ErrRate, codes.ResourceExhausted}} {
		if errors.Is(err, entry.err) {
			code, reason = entry.code, entry.err.Error()
			break
		}
	}
	if errors.Is(err, context.Canceled) {
		code = codes.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	return transportStatus(code, reason, "academic year policy request failed")
}
