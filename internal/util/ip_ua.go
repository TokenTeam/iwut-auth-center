package util

import (
	"context"
)

type IpUA struct{}
type IpUAValue struct {
	Ip string
	UA string
}

// 获取ctx中的 ip UA 作为 审计信息

func RequestIpUAFrom(ctx context.Context) *IpUAValue {
	if v := ctx.Value(IpUA{}); v != nil {
		if s, ok := v.(IpUAValue); ok {
			return &s
		}
	}
	return nil
}

// WithIpUA 将 ip ua 写入 ctx，返回新的 ctx
func WithIpUA(ctx context.Context, value IpUAValue) context.Context {
	return context.WithValue(ctx, IpUA{}, IpUAValue{value.Ip, value.UA})
}
