package transport

import (
	"context"
	"errors"

	"google.golang.org/protobuf/types/known/timestamppb"

	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
	"iwut-auth-center/internal/scope/domain"
)

type GetScopeCatalogSnapshotHandler interface {
	Handle(ctx context.Context) (domain.Snapshot, error)
}

type ScopeCatalogService struct {
	scopecatalogv1.UnimplementedScopeCatalogServer
	handler GetScopeCatalogSnapshotHandler
}

func NewScopeCatalogService(handler GetScopeCatalogSnapshotHandler) *ScopeCatalogService {
	return &ScopeCatalogService{handler: handler}
}

func (service *ScopeCatalogService) GetScopeCatalogSnapshot(
	ctx context.Context,
	_ *scopecatalogv1.GetScopeCatalogSnapshotRequest,
) (*scopecatalogv1.GetScopeCatalogSnapshotResponse, error) {
	if service == nil || service.handler == nil {
		return nil, toTransportError(errInternalTransport)
	}
	snapshot, err := service.handler.Handle(ctx)
	if err != nil {
		return nil, toTransportError(err)
	}

	definitions := make([]*scopecatalogv1.ScopeDefinition, 0, len(snapshot.Scopes()))
	for _, definition := range snapshot.Scopes() {
		definitions = append(definitions, &scopecatalogv1.ScopeDefinition{
			Name:        definition.Name(),
			Requestable: definition.Requestable(),
		})
	}
	return &scopecatalogv1.GetScopeCatalogSnapshotResponse{
		Revision:    snapshot.Revision(),
		GeneratedAt: timestamppb.New(snapshot.GeneratedAt()),
		Scopes:      definitions,
	}, nil
}

var errInternalTransport = errors.New("internal transport failure")

var _ scopecatalogv1.ScopeCatalogServer = (*ScopeCatalogService)(nil)
