package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	"iwut-auth-center/internal/scope/domain"
	"iwut-auth-center/internal/scope/port"
)

type fakeSnapshotHandler struct {
	snapshot domain.Snapshot
	err      error
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
