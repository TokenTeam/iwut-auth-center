package util

import (
	"context"
	"errors"
	"time"

	kratosErrors "github.com/go-kratos/kratos/v2/errors"
)

// Audit 不能引用data\audit.go，避免循环引用
// 为了写泛型写出*了
// 单开Model也许是对的 但目前先不干
type Audit struct {
	ID         *string    `gorm:"primaryKey;column:id;type:char(36)"`  // UUID v4 string
	TraceID    *string    `gorm:"column:trace_id;type:char(32);index"` // trace id as 32 hex chars
	ClientID   *string    `gorm:"column:client_id;type:varchar(128)"`
	UserID     *string    `gorm:"column:user_id;type:varchar(64)"`
	IP         *string    `gorm:"column:ip;type:varchar(45)"`
	UA         *string    `gorm:"column:ua;type:varchar(512)"`
	Function   *string    `gorm:"column:function;type:varchar(128)"`
	FinishAt   *time.Time `gorm:"column:finish_at"`
	ResultCode *int       `gorm:"column:result_code"`
	Message    *string    `gorm:"column:message;type:text"`
}

func GetErrorProcess(funcName string, writeIntoAudit func(ctx context.Context, audit Audit)) func(ctx context.Context, err error, opts ...Audit) error {
	return func(ctx context.Context, err error, opts ...Audit) error {
		traceID := RequestIDFrom(ctx)
		var returnCode int
		var errorMessage string
		var e *kratosErrors.Error
		if errors.As(err, &e) {
			if e.Metadata == nil {
				e.Metadata = map[string]string{}
			}
			e.Metadata["traceId"] = traceID
			errorMessage = e.Message
			returnCode = int(e.Code)
		} else {
			errorMessage = err.Error()
			returnCode = 500
			errNew := kratosErrors.InternalServer("", errorMessage)
			errNew.Metadata = map[string]string{"traceId": traceID}
			err = errNew
		}
		writeIntoAudit(ctx, ReplaceWithOptions(GetAudit(ctx, traceID, funcName, errorMessage, returnCode), opts))
		return err
	}
}

func GetSuccessProcess[T any](funcName string, writeIntoAudit func(ctx context.Context, audit Audit)) func(ctx context.Context, setReqId func(reqId string) T, opts ...Audit) T {
	return func(ctx context.Context, f func(reqId string) T, opts ...Audit) T {
		traceID := RequestIDFrom(ctx)
		writeIntoAudit(ctx, ReplaceWithOptions(GetAudit(ctx, traceID, funcName, "", 200), opts))
		return f(traceID)
	}
}

func ReplaceWithOptions(audit Audit, opts []Audit) Audit {
	if len(opts) == 0 {
		return audit
	}
	for _, o := range opts {
		if o.ID != nil {
			audit.ID = o.ID
		}
		if o.TraceID != nil {
			audit.TraceID = o.TraceID
		}
		if o.ClientID != nil {
			audit.ClientID = o.ClientID
		}
		if o.UserID != nil {
			audit.UserID = o.UserID
		}
		if o.IP != nil {
			audit.IP = o.IP
		}
		if o.UA != nil {
			audit.UA = o.UA
		}
		if o.Function != nil {
			audit.Function = o.Function
		}
		if o.FinishAt != nil {
			audit.FinishAt = o.FinishAt
		}
		if o.ResultCode != nil {
			audit.ResultCode = o.ResultCode
		}
		if o.Message != nil {
			audit.Message = o.Message
		}
	}
	return audit
}

func GetAudit(ctx context.Context, traceID string, funcName string, message string, returnCode int) Audit {
	var clientId, userId string
	if JwtUtilInstance != nil {
		jwtValue := JwtUtilInstance.TokenValueFrom(ctx)
		if jwtValue != nil {
			if jwtValue.BaseAuthClaims != nil {
				userId = jwtValue.BaseAuthClaims.Uid
			} else if jwtValue.OAuthClaims != nil {
				userId = jwtValue.OAuthClaims.Uid
				clientId = jwtValue.OAuthClaims.Azp
			}
		}
	}

	var ip, ua string
	ipUa := RequestIpUAFrom(ctx)
	if ipUa != nil {
		ip = ipUa.Ip
		ua = ipUa.UA
	}
	now := time.Now()
	return Audit{
		TraceID:    &traceID,
		ClientID:   &clientId,
		UserID:     &userId,
		IP:         &ip,
		UA:         &ua,
		Function:   &funcName,
		FinishAt:   &now,
		ResultCode: &returnCode,
		Message:    &message,
	}
}

func GetProcesses[T any](funcName string, writeIntoAudit func(ctx context.Context, audit Audit)) (func(ctx context.Context, setReqId func(reqId string) T, opts ...Audit) T, func(ctx context.Context, err error, opts ...Audit) error) {
	return GetSuccessProcess[T](funcName, writeIntoAudit), GetErrorProcess(funcName, writeIntoAudit)
}
