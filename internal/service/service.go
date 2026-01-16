package service

import (
	"context"
	"iwut-auth-center/internal/biz"
	"iwut-auth-center/internal/util"

	"github.com/google/wire"
)

// ProviderSet is service providers.
var ProviderSet = wire.NewSet(NewAuthService, NewUserService, NewOauth2Service)

// GetAuditInsertFunc builds a function that inserts audit records using the provided AuditUsecase.
// The returned function adapts util.Audit to the AuditUsecase.Repo.InsertAuditForRequest signature and
// is intended to be passed to util.GetProcesses for automatic audit insertion in service handlers.
func GetAuditInsertFunc(usecase biz.AuditUsecase) func(ctx context.Context, audit util.Audit) {
	return func(ctx context.Context, audit util.Audit) {
		usecase.Repo.InsertAuditForRequest(ctx, *audit.TraceID, *audit.ClientID, *audit.UserID, *audit.IP, *audit.Function, *audit.UA, *audit.FinishAt, *audit.ResultCode, *audit.Message)
	}
}
