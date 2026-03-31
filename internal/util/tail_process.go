package util

import (
	"context"
	"errors"
	v1 "iwut-auth-center/api/gen/go/auth_center/v1/error_reason"

	kratosErrors "github.com/go-kratos/kratos/v2/errors"
)

func GetErrorProcess() func(ctx context.Context, err error, userInfo ...UserInfoValue) error {
	return func(ctx context.Context, err error, userInfo ...UserInfoValue) error {
		traceID := RequestIDFrom(ctx)
		var errorMessage string
		var e *kratosErrors.Error
		if errors.As(err, &e) {
			if e.Metadata == nil {
				e.Metadata = map[string]string{}
			}
			e.Metadata["traceId"] = traceID
			errorMessage = e.Message
		} else {
			errorMessage = err.Error()
			errNew := kratosErrors.InternalServer(v1.ErrorReason_UNKNOWN_ERROR.String(), errorMessage)
			errNew.Metadata = map[string]string{"traceId": traceID}
			err = errNew
		}
		if len(userInfo) == 0 {
			SetAudit(ctx, UserInfoValue{})
		} else {
			SetAudit(ctx, userInfo[0])
		}
		return err
	}
}

func GetSuccessProcess[T any]() func(ctx context.Context, setReqId func(reqId string) T, userInfo ...UserInfoValue) T {
	return func(ctx context.Context, f func(reqId string) T, userInfo ...UserInfoValue) T {
		traceID := RequestIDFrom(ctx)
		if len(userInfo) == 0 {
			SetAudit(ctx, UserInfoValue{})
		} else {
			SetAudit(ctx, userInfo[0])
		}
		return f(traceID)
	}
}

func SetAudit(ctx context.Context, userInfo UserInfoValue) {
	audit := RequestAuditFrom(ctx)
	if audit == nil {
		return
	}
	audit.SetUserInfo(userInfo.UserID, userInfo.ClientID)
}

func GetProcesses[T any]() (func(ctx context.Context, setReqId func(reqId string) T, userInfo ...UserInfoValue) T, func(ctx context.Context, err error, userInfo ...UserInfoValue) error) {
	return GetSuccessProcess[T](), GetErrorProcess()
}

type UserInfoValue struct {
	ClientID string
	UserID   string
}
