package util

import (
	"context"

	"github.com/google/uuid"
)

type ReqIDKey struct{}

// 获取ctx中的 reqIDKey 作为 追踪ID

func RequestIDFrom(ctx context.Context) string {
	if v := ctx.Value(ReqIDKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// WithRequestID 将 request id 写入 ctx，返回新的 ctx
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ReqIDKey{}, id)
}

func GenerateRequestID() string {
	return "req-" + uuid.New().String()
}
