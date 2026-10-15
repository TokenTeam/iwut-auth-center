package transport

import (
	"context"
	"testing"
	"time"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/academic_year_policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	d "iwut-auth-center/internal/academicyear/domain"
	academicyearusecase "iwut-auth-center/internal/academicyear/usecase"
)

type academicYearRepositoryStub struct {
	schedule d.Schedule
	command  d.Command
	err      error
}

func (repository *academicYearRepositoryStub) Get(context.Context, string) (d.Schedule, error) {
	return repository.schedule, repository.err
}
func (repository *academicYearRepositoryStub) Update(_ context.Context, command d.Command) (d.Schedule, error) {
	repository.command = command
	return repository.schedule, repository.err
}

type academicYearLimiterStub bool

func (limiter academicYearLimiterStub) AllowBegin(string, time.Time) bool    { return bool(limiter) }
func (limiter academicYearLimiterStub) AllowComplete(string, time.Time) bool { return bool(limiter) }

func TestAcademicYearPolicyTransportPreservesTimestampAndValidatesShape(t *testing.T) {
	next := time.Date(2027, time.February, 20, 1, 2, 3, 456789123, time.UTC)
	repository := &academicYearRepositoryStub{schedule: d.Schedule{CurrentAcademicYear: 2026, NextRolloverAt: next, ObservedAt: time.Date(2026, time.October, 10, 0, 0, 0, 0, time.UTC), Revision: 2, UpdatedAt: time.Date(2026, time.October, 10, 0, 0, 0, 0, time.UTC), UpdatedByAuthID: "admin"}}
	service := NewAcademicYearPolicyService(academicyearusecase.New(repository, academicYearLimiterStub(true)))
	ctx := context.WithValue(context.Background(), userIdentityContextKey{}, "admin")
	revision := int64(1)
	response, err := service.UpdateNextAcademicYearRollover(ctx, &pb.UpdateNextAcademicYearRolloverRequest{NextRolloverAt: timestamppb.New(next), ExpectedRevision: &revision, Reason: " because "})
	if err != nil || !response.NextRolloverAt.AsTime().Equal(next) || !repository.command.NextRolloverAt.Equal(next) || repository.command.Reason != "because" {
		t.Fatalf("response=%#v command=%#v err=%v", response, repository.command, err)
	}
	if _, err = service.UpdateNextAcademicYearRollover(ctx, &pb.UpdateNextAcademicYearRolloverRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid request code = %v, %v", status.Code(err), err)
	}
}

func TestAcademicYearPolicyErrorCodes(t *testing.T) {
	for expected, err := range map[codes.Code]error{
		codes.PermissionDenied:   d.ErrForbidden,
		codes.FailedPrecondition: d.ErrNotFuture,
		codes.Aborted:            d.ErrConflict,
		codes.ResourceExhausted:  d.ErrRate,
		codes.Unavailable:        d.ErrUnavailable,
	} {
		if actual := status.Code(academicYearPolicyError(err)); actual != expected {
			t.Fatalf("%v mapped to %v, want %v", err, actual, expected)
		}
	}
}
