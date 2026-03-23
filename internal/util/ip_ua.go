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

func RequestIpFrom(ctx context.Context) *string {
	if v := ctx.Value(IpUA{}); v != nil {
		if s, ok := v.(IpUAValue); ok {
			return &(s.Ip)
		}
	}
	return nil
}

func RequestUAFrom(ctx context.Context) *string {
	if v := ctx.Value(IpUA{}); v != nil {
		if s, ok := v.(IpUAValue); ok {
			return &(s.UA)
		}
	}
	return nil
}

// WithIpUA 将 ip ua 写入 ctx，返回新的 ctx
func WithIpUA(ctx context.Context, value IpUAValue) context.Context {
	return context.WithValue(ctx, IpUA{}, IpUAValue{value.Ip, value.UA})
}
