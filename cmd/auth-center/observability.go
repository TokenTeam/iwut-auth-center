package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	kratoserrors "github.com/go-kratos/kratos/v2/errors"
	kratoslog "github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	otlpm "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	otlpt "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"iwut-auth-center/internal/config"
)

const (
	serviceName                 = "iwut-auth-center"
	telemetryShutdownTimeout    = 5 * time.Second
	telemetryInstrumentationKey = "iwut-auth-center/transport"
)

type observabilityRuntime struct {
	serverMiddleware            middleware.Middleware
	clientInterceptor           grpc.UnaryClientInterceptor
	directHTTPMiddleware        func(string, http.Handler) http.Handler
	httpNotFoundHandler         http.Handler
	httpMethodNotAllowedHandler http.Handler
	operations                  *observableOperationRegistry
	shutdown                    func(context.Context) error
}

type observableOperationRegistry struct {
	mu    sync.RWMutex
	known map[string]map[string]struct{}
}

func newObservableOperationRegistry() *observableOperationRegistry {
	return &observableOperationRegistry{known: map[string]map[string]struct{}{}}
}

func (registry *observableOperationRegistry) register(kind string, operations []string) {
	bounded := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		if operation != "" {
			bounded[operation] = struct{}{}
		}
	}
	registry.mu.Lock()
	registry.known[kind] = bounded
	registry.mu.Unlock()
}

func (registry *observableOperationRegistry) normalize(kind, operation string) string {
	registry.mu.RLock()
	_, found := registry.known[kind][operation]
	registry.mu.RUnlock()
	if found {
		return operation
	}
	if kind == "" {
		kind = "unknown"
	}
	return kind + ".unmatched"
}

func provideObservability(configuration config.Config) (*observabilityRuntime, func(), error) {
	level, err := parseSlogLevel(configuration.LogLevel)
	if err != nil {
		return nil, nil, err
	}
	slog.SetDefault(slog.New(&traceLogHandler{Handler: slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})}).With("service.name", serviceName))
	kratoslog.SetLogger(kratosSlogLogger{})
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {
		slog.Error("telemetry exporter error", "error.type", "otel_export")
	}))

	ctx, cancel := context.WithTimeout(context.Background(), telemetryShutdownTimeout)
	defer cancel()
	res, err := resource.New(ctx, resource.WithAttributes(attribute.String("service.name", serviceName)))
	if err != nil {
		return nil, nil, fmt.Errorf("build telemetry resource: %w", err)
	}

	propagator := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
	otel.SetTextMapPropagator(propagator)

	traceOptions := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(configuration.TraceSampleRatio))),
	}
	metricOptions := []sdkmetric.Option{sdkmetric.WithResource(res)}
	var metricReader *sdkmetric.PeriodicReader
	if configuration.OTLPGRPCEndpoint != "" {
		traceExporterOptions := []otlpt.Option{otlpt.WithEndpoint(configuration.OTLPGRPCEndpoint)}
		metricExporterOptions := []otlpm.Option{otlpm.WithEndpoint(configuration.OTLPGRPCEndpoint)}
		if configuration.OTLPInsecure {
			traceExporterOptions = append(traceExporterOptions, otlpt.WithInsecure())
			metricExporterOptions = append(metricExporterOptions, otlpm.WithInsecure())
		}
		traceExporter, exportErr := otlpt.New(ctx, traceExporterOptions...)
		if exportErr != nil {
			return nil, nil, fmt.Errorf("create OTLP trace exporter: %w", exportErr)
		}
		metricExporter, exportErr := otlpm.New(ctx, metricExporterOptions...)
		if exportErr != nil {
			_ = traceExporter.Shutdown(ctx)
			return nil, nil, fmt.Errorf("create OTLP metric exporter: %w", exportErr)
		}
		traceOptions = append(traceOptions, sdktrace.WithBatcher(traceExporter))
		metricReader = sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(configuration.MetricExportInterval))
		metricOptions = append(metricOptions, sdkmetric.WithReader(metricReader))
	}

	tracerProvider := sdktrace.NewTracerProvider(traceOptions...)
	meterProvider := sdkmetric.NewMeterProvider(metricOptions...)
	otel.SetTracerProvider(tracerProvider)
	otel.SetMeterProvider(meterProvider)

	meter := meterProvider.Meter(telemetryInstrumentationKey)
	requestCount, err := meter.Int64Counter("auth_center.server.requests", metric.WithUnit("{request}"))
	if err != nil {
		return nil, nil, fmt.Errorf("create request counter: %w", err)
	}
	requestDuration, err := meter.Float64Histogram("auth_center.server.duration", metric.WithUnit("s"))
	if err != nil {
		return nil, nil, fmt.Errorf("create request duration histogram: %w", err)
	}

	shutdown := func(shutdownContext context.Context) error {
		return errors.Join(meterProvider.Shutdown(shutdownContext), tracerProvider.Shutdown(shutdownContext))
	}
	operations := newObservableOperationRegistry()
	runtime := &observabilityRuntime{
		serverMiddleware:     newServerObservabilityMiddleware(tracerProvider, propagator, requestCount, requestDuration, operations.normalize),
		clientInterceptor:    newClientTracingInterceptor(tracerProvider, propagator),
		directHTTPMiddleware: newDirectHTTPObservabilityMiddleware(tracerProvider, propagator, requestCount, requestDuration),
		httpNotFoundHandler:  newHTTPFallbackObservabilityHandler(tracerProvider, propagator, requestCount, requestDuration, http.StatusNotFound, "NOT_FOUND", http.NotFoundHandler()),
		httpMethodNotAllowedHandler: newHTTPFallbackObservabilityHandler(tracerProvider, propagator, requestCount, requestDuration, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		})),
		operations: operations,
		shutdown:   shutdown,
	}
	cleanup := func() {
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), telemetryShutdownTimeout)
		defer shutdownCancel()
		if shutdownErr := shutdown(shutdownContext); shutdownErr != nil {
			slog.Error("flush telemetry", "error.type", "telemetry_shutdown")
		}
	}
	return runtime, cleanup, nil
}

type observabilityResponseWriter struct {
	http.ResponseWriter
	status int
}

func (writer *observabilityResponseWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

func (writer *observabilityResponseWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *observabilityResponseWriter) Write(data []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(data)
}

func newDirectHTTPObservabilityMiddleware(
	provider trace.TracerProvider,
	propagator propagation.TextMapPropagator,
	requestCount metric.Int64Counter,
	requestDuration metric.Float64Histogram,
) func(string, http.Handler) http.Handler {
	tracer := provider.Tracer(telemetryInstrumentationKey)
	return func(operation string, next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			ctx := propagator.Extract(request.Context(), propagation.HeaderCarrier(request.Header))
			ctx, span := tracer.Start(ctx, operation, trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(
				attribute.String("rpc.system", "http"),
				attribute.String("rpc.operation", operation),
			))
			defer span.End()
			started := time.Now()
			observed := &observabilityResponseWriter{ResponseWriter: writer}
			next.ServeHTTP(observed, request.WithContext(ctx))
			if observed.status == 0 {
				observed.status = http.StatusOK
			}
			reason := stableHTTPReason(observed.status)
			duration := time.Since(started).Seconds()
			attrs := []attribute.KeyValue{
				attribute.String("transport", "http"),
				attribute.String("operation", operation),
				attribute.Int("code", observed.status),
				attribute.String("reason", reason),
			}
			requestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
			requestDuration.Record(ctx, duration, metric.WithAttributes(attrs[:2]...))
			span.SetAttributes(attribute.Int("rpc.status_code", observed.status), attribute.String("error.type", reason))
			if observed.status >= http.StatusInternalServerError {
				span.SetStatus(otelcodes.Error, reason)
			}
			slog.InfoContext(ctx, "request completed", "transport", "http", "operation", operation, "code", observed.status, "reason", reason, "duration_ms", duration*1000)
		})
	}
}

func stableHTTPReason(status int) string {
	switch status {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent, http.StatusFound, http.StatusSeeOther:
		return "OK"
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHENTICATED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusMethodNotAllowed:
		return "METHOD_NOT_ALLOWED"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	case http.StatusServiceUnavailable:
		return "UNAVAILABLE"
	default:
		if status >= 500 {
			return "INTERNAL"
		}
		return "HTTP_OTHER"
	}
}

func newHTTPFallbackObservabilityHandler(
	provider trace.TracerProvider,
	propagator propagation.TextMapPropagator,
	requestCount metric.Int64Counter,
	requestDuration metric.Float64Histogram,
	statusCode int,
	reason string,
	next http.Handler,
) http.Handler {
	const operation = "http.unmatched"
	tracer := provider.Tracer(telemetryInstrumentationKey)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := propagator.Extract(request.Context(), propagation.HeaderCarrier(request.Header))
		ctx, span := tracer.Start(ctx, operation, trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(
			attribute.String("rpc.system", "http"),
			attribute.String("rpc.operation", operation),
		))
		defer span.End()
		started := time.Now()
		next.ServeHTTP(writer, request.WithContext(ctx))
		duration := time.Since(started).Seconds()
		attrs := []attribute.KeyValue{
			attribute.String("transport", "http"),
			attribute.String("operation", operation),
			attribute.Int("code", statusCode),
			attribute.String("reason", reason),
		}
		requestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
		requestDuration.Record(ctx, duration, metric.WithAttributes(attrs[:2]...))
		span.SetAttributes(attribute.Int("rpc.status_code", statusCode), attribute.String("error.type", reason))
		if statusCode >= http.StatusInternalServerError {
			span.SetStatus(otelcodes.Error, reason)
		}
		slog.InfoContext(ctx, "request completed",
			"transport", "http",
			"operation", operation,
			"code", statusCode,
			"reason", reason,
			"duration_ms", duration*1000,
		)
	})
}

func parseSlogLevel(raw string) (slog.Level, error) {
	switch strings.ToUpper(raw) {
	case "":
		return slog.LevelInfo, nil
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARN":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", raw)
	}
}

type traceLogHandler struct{ slog.Handler }

func (h *traceLogHandler) Handle(ctx context.Context, record slog.Record) error {
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.HasTraceID() {
		record.AddAttrs(slog.String("trace_id", spanContext.TraceID().String()))
	}
	if spanContext.HasSpanID() {
		record.AddAttrs(slog.String("span_id", spanContext.SpanID().String()))
	}
	return h.Handler.Handle(ctx, record)
}

func (h *traceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceLogHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *traceLogHandler) WithGroup(name string) slog.Handler {
	return &traceLogHandler{Handler: h.Handler.WithGroup(name)}
}

type kratosSlogLogger struct{}

func (kratosSlogLogger) Log(level kratoslog.Level, keyvals ...any) error {
	message := "kratos"
	for index := 0; index+1 < len(keyvals); index += 2 {
		if key, ok := keyvals[index].(string); ok && key == "msg" {
			message = fmt.Sprint(keyvals[index+1])
			break
		}
	}
	slogLevel := slog.LevelInfo
	switch level {
	case kratoslog.LevelDebug:
		slogLevel = slog.LevelDebug
	case kratoslog.LevelWarn:
		slogLevel = slog.LevelWarn
	case kratoslog.LevelError, kratoslog.LevelFatal:
		slogLevel = slog.LevelError
	}
	slog.Log(context.Background(), slogLevel, message, "component", "kratos")
	return nil
}

type transportHeaderCarrier struct{ transport.Header }

func (carrier transportHeaderCarrier) Keys() []string { return carrier.Header.Keys() }

func newServerObservabilityMiddleware(
	provider trace.TracerProvider,
	propagator propagation.TextMapPropagator,
	requestCount metric.Int64Counter,
	requestDuration metric.Float64Histogram,
	normalizeOperation func(string, string) string,
) middleware.Middleware {
	tracer := provider.Tracer(telemetryInstrumentationKey)
	return func(next middleware.Handler) middleware.Handler {
		return func(ctx context.Context, request any) (any, error) {
			kind, operation := "unknown", "unknown"
			if info, ok := transport.FromServerContext(ctx); ok {
				kind = info.Kind().String()
				operation = info.Operation()
				ctx = propagator.Extract(ctx, transportHeaderCarrier{Header: info.RequestHeader()})
			}
			operation = normalizeOperation(kind, operation)
			ctx, span := tracer.Start(ctx, operation, trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(
				attribute.String("rpc.system", kind),
				attribute.String("rpc.operation", operation),
			))
			defer span.End()

			started := time.Now()
			reply, err := next(ctx, request)
			code, reason := requestOutcome(err)
			duration := time.Since(started).Seconds()
			attrs := []attribute.KeyValue{
				attribute.String("transport", kind),
				attribute.String("operation", operation),
				attribute.Int("code", code),
				attribute.String("reason", reason),
			}
			requestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
			requestDuration.Record(ctx, duration, metric.WithAttributes(attrs[:2]...))
			span.SetAttributes(attribute.Int("rpc.status_code", code), attribute.String("error.type", reason))
			if err != nil {
				span.SetStatus(otelcodes.Error, reason)
			}
			slog.InfoContext(ctx, "request completed",
				"transport", kind,
				"operation", operation,
				"code", code,
				"reason", reason,
				"duration_ms", duration*1000,
			)
			return reply, err
		}
	}
}

func requestOutcome(err error) (int, string) {
	if err == nil {
		return 200, ""
	}
	if typed := kratoserrors.FromError(err); typed != nil {
		return int(typed.Code), typed.Reason
	}
	return 500, "INTERNAL"
}

type metadataCarrier metadata.MD

func (carrier metadataCarrier) Get(key string) string {
	values := metadata.MD(carrier).Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (carrier metadataCarrier) Set(key, value string) { metadata.MD(carrier).Set(key, value) }

func (carrier metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(carrier))
	for key := range carrier {
		keys = append(keys, key)
	}
	return keys
}

func newClientTracingInterceptor(provider trace.TracerProvider, propagator propagation.TextMapPropagator) grpc.UnaryClientInterceptor {
	tracer := provider.Tracer(telemetryInstrumentationKey)
	return func(ctx context.Context, method string, request, reply any, connection *grpc.ClientConn, invoke grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(
			attribute.String("rpc.system", "grpc"),
			attribute.String("rpc.operation", method),
		))
		defer span.End()
		outgoing, _ := metadata.FromOutgoingContext(ctx)
		outgoing = outgoing.Copy()
		propagator.Inject(ctx, metadataCarrier(outgoing))
		ctx = metadata.NewOutgoingContext(ctx, outgoing)
		err := invoke(ctx, method, request, reply, connection, opts...)
		grpcCode := status.Code(err)
		span.SetAttributes(attribute.String("rpc.grpc.status_code", grpcCode.String()))
		if err != nil {
			span.SetStatus(otelcodes.Error, grpcCode.String())
		}
		return err
	}
}
