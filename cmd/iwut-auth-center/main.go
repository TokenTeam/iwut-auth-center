package main

import (
	"context"
	"flag"
	"fmt"
	"iwut-auth-center/internal/util"
	"net/url"
	"os"
	"strings"

	"iwut-auth-center/internal/conf"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/env"
	"github.com/go-kratos/kratos/v2/config/file"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otlptrace "go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	otlptracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"

	kzap "github.com/go-kratos/kratos/contrib/log/zap/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	_ "go.uber.org/automaxprocs"
)

// go build -ldflags "-X main.Version=x.y.z"
var (
	// Name is the name of the compiled software.
	Name string
	// Version is the version of the compiled software.
	Version string
	// flagconf is the config flag.
	flagconf string

	id, _ = os.Hostname()
)

func newTracerProvider(jaegerEndPoint string) *trace.TracerProvider {

	// Interpret the provided endpoint. If it's an HTTP URL, extract host:port.
	// Default to the OTLP gRPC default endpoint if empty or cannot parse.
	endpoint := jaegerEndPoint
	if endpoint == "" {
		endpoint = "localhost:4317"
	} else {
		if u, err := url.Parse(endpoint); err == nil && u.Scheme != "" {
			// If URL contains a host component use it (host:port); otherwise keep original
			if u.Host != "" {
				endpoint = u.Host
			}
		}
	}

	// Create OTLP gRPC exporter client. Use insecure connection for plaintext.
	ctx := context.Background()
	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		// If exporter can't be created, return a basic tracer provider so app can continue.
		_ = err
		tp := trace.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return tp
	}

	// Prepare resource with service information. Caller should set Name and Version
	// before calling this function.
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", Name),
			attribute.String("service.version", Version),
		),
	)
	if err != nil {
		res = resource.Default()
	}

	// Use batcher for better performance in production
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	// Set global propagator to ensure trace context is propagated across service boundaries
	// This is critical for distributed tracing to work correctly
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp
}

func init() {
	flag.StringVar(&flagconf, "conf", "configs", "config path, eg: -conf config.yaml")
}

func newApp(logger log.Logger, gs *grpc.Server, hs *http.Server) *kratos.App {
	return kratos.New(
		kratos.ID(id),
		kratos.Name(Name),
		kratos.Version(Version),
		kratos.Metadata(map[string]string{}),
		kratos.Logger(logger),
		kratos.Server(
			gs,
			hs,
		),
	)
}

func newLogger(bc *conf.Bootstrap) log.Logger {
	// 1. 配置 Zap 输出 JSON 格式到标准输出 (stdout)
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "time"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder // 易读的时间格式

	zapCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		zap.InfoLevel,
	)
	zLogger := zap.New(zapCore)

	// 2. 将 Zap 包装为 Kratos 的 Logger
	kratosZap := kzap.NewLogger(zLogger)

	logger := log.With(kratosZap,
		"ts", log.DefaultTimestamp,
		"caller", log.DefaultCaller,
		"service_id", id,
		"service_name", Name,
		"service_version", Version,
		"trace_id", tracing.TraceID(),
		"span_id", tracing.SpanID(),
	)
	if logLevel := bc.GetServer().GetEnv(); !strings.HasPrefix(strings.ToLower(logLevel), "dev") {
		// PROD 环境：过滤日志级别并脱敏请求参数
		logger = log.NewFilter(logger,
			// 功能A：过滤日志级别（例如只打印 Info 及以上级别，丢弃 Debug）
			log.FilterLevel(log.LevelInfo),

			log.FilterFunc(func(level log.Level, kvs ...interface{}) bool {
				// 遍历所有即将打印的键值对
				for i := 0; i < len(kvs); i += 2 {
					key, ok := kvs[i].(string)
					if !ok {
						continue
					}
					// 针对 Kratos 默认打印的请求参数（键名通常为 "args"）
					if key == "args" && i+1 < len(kvs) {
						// Kratos 的 args 可能是一个 Protobuf 结构体，将其转为字符串
						originalStr := fmt.Sprintf("%v", kvs[i+1])
						maskedStr := util.MaskArgsString(originalStr)
						// 替换原有的值
						kvs[i+1] = maskedStr
					}
				}
				return false // 返回 false 表示处理完毕，继续打印；返回 true 会直接丢弃整条日志
			}),
		)
	}

	return logger
}

func main() {
	flag.Parse()

	c := config.New(
		config.WithSource(
			env.NewSource("AuthCenter_"),
			file.NewSource(flagconf),
		),
	)
	defer func(c config.Config) {
		_ = c.Close()
	}(c)

	if err := c.Load(); err != nil {
		panic(err)
	}

	var bc conf.Bootstrap
	if err := c.Scan(&bc); err != nil {
		panic(err)
	}

	if Name == "" {
		Name = bc.Server.GetName()
	}
	if Version == "" {
		Version = bc.Server.GetVersion()
	}

	// 初始化 tracer：在已设置 Name/Version 后创建
	tp := newTracerProvider(bc.Server.GetJaegerEndpoint())
	defer func() { _ = tp.Shutdown(context.Background()) }()

	logger := newLogger(&bc)

	app, cleanup, err := wireApp(bc.Server, bc.Data, bc.Jwt, bc.Mail, bc.Service, logger)
	if err != nil {
		panic(err)
	}
	defer cleanup()

	// start and wait for stop signal
	if err := app.Run(); err != nil {
		panic(err)
	}
}
