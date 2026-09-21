package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	developerstatusv1 "iwut-auth-center/api/gen/go/auth_center/v1/developer_status"
	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	developerdomain "iwut-auth-center/internal/developer/domain"
	developerport "iwut-auth-center/internal/developer/port"
	developerusecase "iwut-auth-center/internal/developer/usecase"
	"iwut-auth-center/internal/scope/domain"
	"iwut-auth-center/internal/scope/port"
)

type fakeSnapshotHandler struct {
	snapshot domain.Snapshot
	err      error
}

type fakeDeveloperStatusHandler struct {
	entries []developerusecase.DeveloperStatusEntry
	err     error
	gotIDs  []string
}

func (handler *fakeDeveloperStatusHandler) Handle(_ context.Context, authIDs []string) ([]developerusecase.DeveloperStatusEntry, error) {
	handler.gotIDs = append([]string(nil), authIDs...)
	return handler.entries, handler.err
}

func TestDeveloperStatusService_BR_DEV_003_PreservesRequestOrder(t *testing.T) {
	first, _ := developerdomain.NewAuthID("suspended")
	second, _ := developerdomain.NewAuthID("approved")
	handler := &fakeDeveloperStatusHandler{entries: []developerusecase.DeveloperStatusEntry{
		{AuthID: first, DeveloperStatus: developerdomain.DeveloperStatusSuspended},
		{AuthID: second, DeveloperStatus: developerdomain.DeveloperStatusApproved},
	}}
	service := NewDeveloperStatusService(handler)

	response, err := service.BatchGetDeveloperStatuses(t.Context(), &developerstatusv1.BatchGetDeveloperStatusesRequest{
		AuthIds: []string{"suspended", "approved"},
	})
	if err != nil {
		t.Fatalf("BatchGetDeveloperStatuses() error = %v", err)
	}
	if len(handler.gotIDs) != 2 || handler.gotIDs[0] != "suspended" || handler.gotIDs[1] != "approved" {
		t.Fatalf("handler IDs = %v", handler.gotIDs)
	}
	entries := response.GetEntries()
	if len(entries) != 2 || entries[0].GetAuthId() != "suspended" || entries[0].GetDeveloperStatus() != developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_SUSPENDED || entries[1].GetAuthId() != "approved" || entries[1].GetDeveloperStatus() != developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_APPROVED {
		t.Fatalf("response entries = %v", entries)
	}
}

func TestDeveloperStatusService_MapsEveryPublishedStatus(t *testing.T) {
	tests := []struct {
		domain developerdomain.DeveloperStatus
		proto  developerstatusv1.DeveloperStatus
	}{
		{domain: developerdomain.DeveloperStatusPending, proto: developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_PENDING},
		{domain: developerdomain.DeveloperStatusApproved, proto: developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_APPROVED},
		{domain: developerdomain.DeveloperStatusRejected, proto: developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_REJECTED},
		{domain: developerdomain.DeveloperStatusSuspended, proto: developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_SUSPENDED},
	}
	for _, testCase := range tests {
		got, ok := developerStatusToProto(testCase.domain)
		if !ok || got != testCase.proto {
			t.Fatalf("developerStatusToProto(%q) = (%v, %t), want (%v, true)", testCase.domain, got, ok, testCase.proto)
		}
	}
	if got, ok := developerStatusToProto(""); ok || got != developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_UNSPECIFIED {
		t.Fatalf("developerStatusToProto(empty) = (%v, %t)", got, ok)
	}
}

func TestDeveloperStatusService_MapsStableErrorsWithoutLeakingCause(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		code   codes.Code
		reason string
	}{
		{name: "invalid", err: developerusecase.ErrInvalidDeveloperStatusQuery, code: codes.InvalidArgument, reason: ReasonInvalidDeveloperStatusQuery},
		{name: "not found", err: developerusecase.ErrDeveloperStatusNotFound, code: codes.NotFound, reason: ReasonDeveloperStatusNotFound},
		{name: "unavailable", err: errors.Join(developerport.ErrDeveloperStatusUnavailable, errors.New("mongodb://secret-host/internal")), code: codes.Unavailable, reason: ReasonDeveloperStatusUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewDeveloperStatusService(&fakeDeveloperStatusHandler{err: test.err})
			_, err := service.BatchGetDeveloperStatuses(t.Context(), &developerstatusv1.BatchGetDeveloperStatusesRequest{})
			current := status.Convert(err)
			if current.Code() != test.code || strings.Contains(current.Message(), "secret-host") {
				t.Fatalf("status = (%v, %q)", current.Code(), current.Message())
			}
			foundReason := false
			for _, detail := range current.Details() {
				if info, ok := detail.(*errdetails.ErrorInfo); ok && info.GetReason() == test.reason {
					foundReason = true
				}
			}
			if !foundReason {
				t.Fatalf("status details = %v", current.Details())
			}
		})
	}
}

func (handler *fakeSnapshotHandler) Handle(context.Context) (domain.Snapshot, error) {
	return handler.snapshot, handler.err
}

func TestScopeCatalogService_BR_SCP_002_MapsCompleteSnapshot(t *testing.T) {
	second, _ := domain.NewScopeDefinition("schedule.read", false)
	first, _ := domain.NewScopeDefinition("profile.basic", true)
	generatedAt := time.Date(2026, time.September, 21, 0, 0, 0, 0, time.UTC)
	snapshot, _ := domain.NewSnapshot(9, generatedAt, []domain.ScopeDefinition{second, first})
	service := NewScopeCatalogService(&fakeSnapshotHandler{snapshot: snapshot})

	response, err := service.GetScopeCatalogSnapshot(t.Context(), &scopecatalogv1.GetScopeCatalogSnapshotRequest{})
	if err != nil {
		t.Fatalf("GetScopeCatalogSnapshot() error = %v", err)
	}
	if response.GetRevision() != 9 || !response.GetGeneratedAt().AsTime().Equal(generatedAt) {
		t.Fatalf("response metadata = (%d, %v)", response.GetRevision(), response.GetGeneratedAt())
	}
	if len(response.GetScopes()) != 2 || response.GetScopes()[0].GetName() != "profile.basic" || !response.GetScopes()[0].GetRequestable() {
		t.Fatalf("response scopes = %v", response.GetScopes())
	}
}

func TestScopeCatalogService_MapsUnavailableWithoutLeakingCause(t *testing.T) {
	service := NewScopeCatalogService(&fakeSnapshotHandler{
		err: errors.Join(port.ErrScopeCatalogUnavailable, errors.New("mongodb://secret-host/internal")),
	})
	_, err := service.GetScopeCatalogSnapshot(t.Context(), &scopecatalogv1.GetScopeCatalogSnapshotRequest{})
	current := status.Convert(err)
	if current.Code() != codes.Unavailable || current.Message() != "scope catalog is unavailable" {
		t.Fatalf("status = (%v, %q)", current.Code(), current.Message())
	}
	foundReason := false
	for _, detail := range current.Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.GetReason() == ReasonScopeCatalogUnavailable {
			foundReason = true
		}
	}
	if !foundReason {
		t.Fatalf("status details = %v", current.Details())
	}
}
