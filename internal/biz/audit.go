package biz

import (
	"context"
	"time"
)

type AuditRepo interface {
	InsertAuditForRequest(ctx context.Context, traceID, clientID, userID, ip, function, ua string, finishAt time.Time, resultCode int, errMsg string)
	Close()
}

type AuditUsecase struct {
	Repo AuditRepo
}

func NewAuditUsecase(repo AuditRepo) *AuditUsecase {
	return &AuditUsecase{Repo: repo}
}
