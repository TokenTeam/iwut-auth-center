package server

import (
	authpb "iwut-auth-center/api/auth_center/v1/auth"
	oauth2pb "iwut-auth-center/api/auth_center/v1/oauth2"
	userpb "iwut-auth-center/api/auth_center/v1/user"
	"iwut-auth-center/internal/conf"
	"iwut-auth-center/internal/middleware"
	"iwut-auth-center/internal/service"
	"strings"

	"github.com/go-kratos/kratos/v2/encoding"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/transport/http"
)

// CodecForRequest get codec from request header.
// 这是 Kratos 框架内部实现的CV + 展开
func CodecForRequest(r *http.Request, name string) (encoding.Codec, bool) {
	for _, accept := range r.Header[name] {
		contentSubtype := ""
		left := strings.Index(accept, "/")
		if left != -1 {
			right := strings.Index(accept, ";")
			if right == -1 {
				right = len(accept)
			}
			if right >= left {
				contentSubtype = accept[left+1 : right]
			}
		}
		codec := encoding.GetCodec(contentSubtype)
		if codec != nil {
			return codec, true
		}
	}
	return encoding.GetCodec("json"), false
}
func CreatedErrorEncoder(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(200)
	se := errors.FromError(err)
	codec, _ := CodecForRequest(r, "Accept")
	returnErr := struct {
		Code    int32   `json:"code"`
		Message string  `json:"message"`
		TraceId *string `json:"traceId,omitempty"`
	}{
		Code:    se.Code,
		Message: se.Message,
	}
	// 检查se有没有 GetMetadata 方法，如果有则调用它
	if mdGetter, ok := interface{}(se).(interface {
		GetMetadata() map[string]string
	}); ok {
		for k, v := range mdGetter.GetMetadata() {
			if k == "traceId" {
				returnErr.TraceId = &v
			}
		}
	}

	body, err := codec.Marshal(returnErr)

	w.Header().Set("Content-Type", "application"+"/"+codec.Name())
	_, _ = w.Write(body)
}

// NewHTTPServer new an HTTP server.
func NewHTTPServer(c *conf.Server, authSvc *service.AuthService, userSvc *service.UserService, oauth2Service *service.Oauth2Service, jwtCheck *middleware.JwtCheckMiddleware, logger log.Logger) *http.Server {
	var opts = []http.ServerOption{
		http.Middleware(
			recovery.Recovery(),
			tracing.Server(),
			logging.Server(logger),
			middleware.GetAuditInfoCollectorMiddleware(),
			jwtCheck.GetCheckJwtMiddleware(),
		),
		http.ErrorEncoder(CreatedErrorEncoder),
	}
	if c.Http.Network != "" {
		opts = append(opts, http.Network(c.Http.Network))
	}
	if c.Http.Addr != "" {
		opts = append(opts, http.Address(c.Http.Addr))
	}
	if c.Http.Timeout != nil {
		opts = append(opts, http.Timeout(c.Http.Timeout.AsDuration()))
	}
	srv := http.NewServer(opts...)
	authpb.RegisterAuthHTTPServer(srv, authSvc)
	userpb.RegisterUserHTTPServer(srv, userSvc)
	oauth2pb.RegisterOAuth2HTTPServer(srv, oauth2Service)
	return srv
}
