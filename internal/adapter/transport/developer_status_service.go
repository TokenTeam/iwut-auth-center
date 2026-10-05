package transport

import (
	"context"

	developerstatusv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_status"
	"iwut-auth-center/internal/developer/domain"
	developerusecase "iwut-auth-center/internal/developer/usecase"
)

type BatchGetDeveloperStatusesHandler interface {
	Handle(ctx context.Context, authIDs []string) ([]developerusecase.DeveloperStatusEntry, error)
}

type DeveloperStatusService struct {
	developerstatusv1.UnimplementedDeveloperStatusDirectoryServer
	handler BatchGetDeveloperStatusesHandler
}

func NewDeveloperStatusService(handler BatchGetDeveloperStatusesHandler) *DeveloperStatusService {
	return &DeveloperStatusService{handler: handler}
}

func (service *DeveloperStatusService) BatchGetDeveloperStatuses(
	ctx context.Context,
	request *developerstatusv1.BatchGetDeveloperStatusesRequest,
) (*developerstatusv1.BatchGetDeveloperStatusesResponse, error) {
	if service == nil || service.handler == nil || request == nil {
		return nil, toTransportError(errInternalTransport)
	}
	entries, err := service.handler.Handle(ctx, request.GetAuthIds())
	if err != nil {
		return nil, toTransportError(err)
	}
	responseEntries := make([]*developerstatusv1.DeveloperStatusEntry, 0, len(entries))
	for _, entry := range entries {
		status, ok := developerStatusToProto(entry.DeveloperStatus)
		account, accountOK := developerstatusv1.AccountStatus_value["ACCOUNT_STATUS_"+string(entry.AccountStatus)]
		if entry.AccountStatus == domain.AccountClosed && entry.DeveloperStatus == "" {
			status = developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_UNSPECIFIED
			ok = true
		}
		if !ok || !accountOK || account == 0 {
			return nil, toTransportError(errInternalTransport)
		}
		responseEntries = append(responseEntries, &developerstatusv1.DeveloperStatusEntry{
			AuthId:          entry.AuthID.String(),
			DeveloperStatus: status,
			AccountStatus:   developerstatusv1.AccountStatus(account),
		})
	}
	return &developerstatusv1.BatchGetDeveloperStatusesResponse{Entries: responseEntries}, nil
}

func developerStatusToProto(status domain.DeveloperStatus) (developerstatusv1.DeveloperStatus, bool) {
	switch status {
	case domain.DeveloperStatusPending:
		return developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_PENDING, true
	case domain.DeveloperStatusApproved:
		return developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_APPROVED, true
	case domain.DeveloperStatusRejected:
		return developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_REJECTED, true
	case domain.DeveloperStatusWithdrawn:
		return developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_WITHDRAWN, true
	case domain.DeveloperStatusSuspended:
		return developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_SUSPENDED, true
	default:
		return developerstatusv1.DeveloperStatus_DEVELOPER_STATUS_UNSPECIFIED, false
	}
}

var _ developerstatusv1.DeveloperStatusDirectoryServer = (*DeveloperStatusService)(nil)
