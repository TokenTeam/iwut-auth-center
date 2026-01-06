package middleware

import (
	"context"
	"iwut-auth-center/internal/util"
	"net"
	"strings"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func GetAuditInfoCollectorMiddleware() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			tr, ok := transport.FromServerContext(ctx)
			if !ok || tr == nil {
				return nil, errors.InternalServer("500", "transport not found in context")
			}
			switch tr.(type) {
			case *http.Transport:
				ip, ua := getIPAndUA(tr)
				ctx = util.WithIpUA(ctx, util.IpUAValue{
					Ip: ip,
					UA: ua,
				})
			case *grpc.Transport:
				p, ok := peer.FromContext(ctx)
				if !ok {
					return nil, errors.InternalServer("500", "p not found in context")
				}
				md, ok := metadata.FromIncomingContext(ctx)
				if !ok {
					return nil, errors.InternalServer("500", "metadata not found in context")
				}
				ip, ua := getGrpcIPAndUA(*p, md)
				ctx = util.WithIpUA(ctx, util.IpUAValue{
					Ip: ip,
					UA: ua,
				})
			default:
				return "", errors.InternalServer("500", "transport type unknown")
			}

			return handler(ctx, req)
		}
	}
}

func getIPAndUA(tr transport.Transporter) (ip, ua string) {

	if ht, ok := tr.(*http.Transport); ok {
		r := ht.Request()
		ua = r.UserAgent()

		// 优先从 X-Forwarded-For / X-Real-IP 取真实 IP
		ip = clientIP(r.RemoteAddr)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip = strings.TrimSpace(parts[0])
		} else if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			ip = xrip
		}
	}

	return
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func getGrpcIPAndUA(p peer.Peer, md metadata.MD) (ip, ua string) {
	if p.Addr != nil {
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err == nil {
			ip = host
		} else {
			ip = p.Addr.String()
		}
	}
	if v := md.Get("user-agent"); len(v) > 0 {
		ua = v[0]
	}
	// 如果有代理，可再读 x-forwarded-for
	return
}
