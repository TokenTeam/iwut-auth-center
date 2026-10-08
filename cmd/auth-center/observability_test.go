package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kratoserrors "github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/transport"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"iwut-auth-center/internal/config"
)

type testTraceCollector struct {
	collectortracepb.UnimplementedTraceServiceServer
	received chan struct{}
}

func (collector *testTraceCollector) Export(_ context.Context, request *collectortracepb.ExportTraceServiceRequest) (*collectortracepb.ExportTraceServiceResponse, error) {
	if len(request.GetResourceSpans()) > 0 {
		select {
		case collector.received <- struct{}{}:
		default:
		}
	}
	return &collectortracepb.ExportTraceServiceResponse{}, nil
}

type testMetricsCollector struct {
	collectormetricspb.UnimplementedMetricsServiceServer
	received chan struct{}
}

func (collector *testMetricsCollector) Export(_ context.Context, request *collectormetricspb.ExportMetricsServiceRequest) (*collectormetricspb.ExportMetricsServiceResponse, error) {
	if len(request.GetResourceMetrics()) > 0 {
		select {
		case collector.received <- struct{}{}:
		default:
		}
	}
	return &collectormetricspb.ExportMetricsServiceResponse{}, nil
}

type observabilityTestHeader map[string][]string

func (header observabilityTestHeader) Get(key string) string {
	values := header.Values(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
func (header observabilityTestHeader) Set(key, value string) {
	header[strings.ToLower(key)] = []string{value}
}
func (header observabilityTestHeader) Add(key, value string) {
	key = strings.ToLower(key)
	header[key] = append(header[key], value)
}
func (header observabilityTestHeader) Keys() []string {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	return keys
}
func (header observabilityTestHeader) Values(key string) []string {
	return header[strings.ToLower(key)]
}

type observabilityTestTransport struct {
	header    observabilityTestHeader
	kind      transport.Kind
	operation string
}

func (tr observabilityTestTransport) Kind() transport.Kind            { return tr.kind }
func (observabilityTestTransport) Endpoint() string                   { return "http://example.test" }
func (tr observabilityTestTransport) Operation() string               { return tr.operation }
func (tr observabilityTestTransport) RequestHeader() transport.Header { return tr.header }
func (tr observabilityTestTransport) ReplyHeader() transport.Header   { return tr.header }

func TestServerObservability_RedactsPayloadAndCorrelatesTrace(t *testing.T) {
	previousLogger := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(&traceLogHandler{Handler: slog.NewJSONHandler(&output, nil)}))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	recorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })
	meter := meterProvider.Meter("test")
	counter, _ := meter.Int64Counter("test.requests")
	duration, _ := meter.Float64Histogram("test.duration")
	propagator := propagation.TraceContext{}
	operations := newObservableOperationRegistry()
	operations.register("http", []string{"/v1/users/me/profile"})

	header := observabilityTestHeader{}
	header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	ctx := transport.NewServerContext(context.Background(), observabilityTestTransport{header: header, kind: transport.KindHTTP, operation: "/v1/users/me/profile"})
	middleware := newServerObservabilityMiddleware(tracerProvider, propagator, counter, duration, operations.normalize)
	_, err := middleware(func(ctx context.Context, request any) (any, error) {
		return nil, kratoserrors.New(409, "VERSION_CONFLICT", "secret=must-not-appear")
	})(ctx, map[string]string{"authorization": "Bearer must-not-appear"})
	if err == nil {
		t.Fatal("middleware error = nil")
	}

	logged := output.String()
	for _, forbidden := range []string{"must-not-appear", "authorization", "secret="} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("log contains sensitive value %q: %s", forbidden, logged)
		}
	}
	for _, required := range []string{"VERSION_CONFLICT", "/v1/users/me/profile", "4bf92f3577b34da6a3ce929d0e0e4736"} {
		if !strings.Contains(logged, required) {
			t.Fatalf("log missing %q: %s", required, logged)
		}
	}
	ended := recorder.Ended()
	if len(ended) != 1 || ended[0].SpanContext().TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("ended spans = %#v", ended)
	}
	assertSpanRedacted(t, ended[0], "must-not-appear", "authorization", "secret=")
	assertServerMetrics(t, reader, "/v1/users/me/profile", 409, "VERSION_CONFLICT")
}

func TestServerObservability_ExtractsTraceContextForHTTPAndGRPC(t *testing.T) {
	for _, kind := range []transport.Kind{transport.KindHTTP, transport.KindGRPC} {
		t.Run(kind.String(), func(t *testing.T) {
			recorder := tracetest.NewSpanRecorder()
			tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
			t.Cleanup(func() { _ = tracerProvider.Shutdown(context.Background()) })
			meterProvider := sdkmetric.NewMeterProvider()
			t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })
			meter := meterProvider.Meter("test")
			counter, _ := meter.Int64Counter("test.requests")
			duration, _ := meter.Float64Histogram("test.duration")
			operations := newObservableOperationRegistry()
			operations.register(kind.String(), []string{"test.operation"})
			header := observabilityTestHeader{}
			header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
			header.Set("baggage", "deployment=test")
			ctx := transport.NewServerContext(context.Background(), observabilityTestTransport{header: header, kind: kind, operation: "test.operation"})
			propagator := propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{})
			middleware := newServerObservabilityMiddleware(tracerProvider, propagator, counter, duration, operations.normalize)
			if _, err := middleware(func(callContext context.Context, _ any) (any, error) {
				if baggage.FromContext(callContext).Member("deployment").Value() != "test" {
					t.Fatal("baggage was not extracted")
				}
				return nil, nil
			})(ctx, nil); err != nil {
				t.Fatalf("middleware error = %v", err)
			}
			ended := recorder.Ended()
			if len(ended) != 1 || ended[0].SpanContext().TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
				t.Fatalf("ended spans = %#v", ended)
			}
		})
	}
}

func TestClientTracingInterceptor_InjectsTraceContext(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	member, _ := baggage.NewMember("deployment", "test")
	bag, _ := baggage.New(member)
	ctx := baggage.ContextWithBaggage(context.Background(), bag)
	ctx, parent := provider.Tracer("test").Start(ctx, "parent", trace.WithSpanKind(trace.SpanKindInternal))
	interceptor := newClientTracingInterceptor(provider, propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	err := interceptor(ctx, "/auth.Test/Call", nil, nil, nil, func(callContext context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		outgoing, found := metadata.FromOutgoingContext(callContext)
		traceparents := outgoing.Get("traceparent")
		if !found || len(traceparents) != 1 || traceparents[0] == "" {
			t.Fatalf("outgoing metadata = %#v", outgoing)
		}
		if values := outgoing.Get("baggage"); len(values) != 1 || !strings.Contains(values[0], "deployment=test") {
			t.Fatalf("outgoing baggage = %#v", values)
		}
		return nil
	})
	parent.End()
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
	if len(recorder.Ended()) != 2 {
		t.Fatalf("ended spans = %d, want 2", len(recorder.Ended()))
	}
}

func TestDirectHTTPObservability_RedactsOAuthRequestAndRecordsMetrics(t *testing.T) {
	previousLogger := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(&traceLogHandler{Handler: slog.NewJSONHandler(&output, nil)}))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })
	meter := meterProvider.Meter("test")
	counter, _ := meter.Int64Counter("test.requests")
	duration, _ := meter.Float64Histogram("test.duration")
	wrap := newDirectHTTPObservabilityMiddleware(provider, propagation.TraceContext{}, counter, duration)
	handler := wrap("oauth.token", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Set-Cookie", "secret-cookie")
		http.Error(writer, "access_token=secret-token", http.StatusUnauthorized)
	}))
	request := httptest.NewRequest(http.MethodPost, "/token?client_secret=secret-client", strings.NewReader("code=secret-code&email=student@example.test"))
	request.Header.Set("Authorization", "Basic secret-authorization")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
	for _, forbidden := range []string{"secret-cookie", "secret-token", "secret-client", "secret-code", "student@example.test", "secret-authorization", "/token?"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("log contains %q: %s", forbidden, output.String())
		}
	}
	if ended := recorder.Ended(); len(ended) != 1 || ended[0].Name() != "oauth.token" {
		t.Fatalf("ended spans = %#v", ended)
	} else {
		assertSpanRedacted(t, ended[0], "secret-cookie", "secret-token", "secret-client", "secret-code", "student@example.test", "secret-authorization")
	}
	assertServerMetrics(t, reader, "oauth.token", http.StatusUnauthorized, "UNAUTHENTICATED")
}

func TestHTTPFallbackObservability_ExtractsTraceAndRecordsBoundedMetrics(t *testing.T) {
	previousLogger := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(&traceLogHandler{Handler: slog.NewJSONHandler(&output, nil)}))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })
	meter := meterProvider.Meter("test")
	counter, _ := meter.Int64Counter("test.requests")
	duration, _ := meter.Float64Histogram("test.duration")
	handler := newHTTPFallbackObservabilityHandler(provider, propagation.TraceContext{}, counter, duration, http.StatusNotFound, "NOT_FOUND", http.NotFoundHandler())
	request := httptest.NewRequest(http.MethodGet, "/attacker-controlled", nil)
	request.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	recorderHTTP := httptest.NewRecorder()
	handler.ServeHTTP(recorderHTTP, request)
	if recorderHTTP.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorderHTTP.Code)
	}
	ended := recorder.Ended()
	if len(ended) != 1 || ended[0].Name() != "http.unmatched" || ended[0].SpanContext().TraceID().String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("ended spans = %#v", ended)
	}
	if strings.Contains(output.String(), "/attacker-controlled") || !strings.Contains(output.String(), "http.unmatched") {
		t.Fatalf("fallback log = %s", output.String())
	}
	assertServerMetrics(t, reader, "http.unmatched", http.StatusNotFound, "NOT_FOUND")
}

func TestHTTPMethodFallbackObservability_UsesFixedOperation(t *testing.T) {
	previousLogger := slog.Default()
	var output bytes.Buffer
	slog.SetDefault(slog.New(&traceLogHandler{Handler: slog.NewJSONHandler(&output, nil)}))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = meterProvider.Shutdown(context.Background()) })
	meter := meterProvider.Meter("test")
	counter, _ := meter.Int64Counter("test.requests")
	duration, _ := meter.Float64Histogram("test.duration")
	handler := newHTTPFallbackObservabilityHandler(provider, propagation.TraceContext{}, counter, duration, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/private/attacker-value", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(output.String(), "/private/attacker-value") || !strings.Contains(output.String(), "http.unmatched") {
		t.Fatalf("fallback log = %s", output.String())
	}
	if ended := recorder.Ended(); len(ended) != 1 || ended[0].Name() != "http.unmatched" {
		t.Fatalf("ended spans = %#v", ended)
	}
	assertServerMetrics(t, reader, "http.unmatched", http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func TestProvideObservability_ExportsTraceAndMetricsToOTLP(t *testing.T) {
	restoreObservabilityGlobals(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := grpc.NewServer()
	traceReceived := make(chan struct{}, 1)
	metricsReceived := make(chan struct{}, 1)
	collectortracepb.RegisterTraceServiceServer(server, &testTraceCollector{received: traceReceived})
	collectormetricspb.RegisterMetricsServiceServer(server, &testMetricsCollector{received: metricsReceived})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	runtime, _, err := provideObservability(config.Config{
		LogLevel:             "INFO",
		OTLPGRPCEndpoint:     listener.Addr().String(),
		OTLPInsecure:         true,
		TraceSampleRatio:     1,
		MetricExportInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("provideObservability() error = %v", err)
	}
	runtime.operations.register("http", []string{"test.operation"})
	ctx := transport.NewServerContext(context.Background(), observabilityTestTransport{header: observabilityTestHeader{}, kind: transport.KindHTTP, operation: "test.operation"})
	if _, err := runtime.serverMiddleware(func(context.Context, any) (any, error) { return nil, nil })(ctx, nil); err != nil {
		t.Fatalf("middleware error = %v", err)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), telemetryShutdownTimeout)
	defer cancel()
	if err := runtime.shutdown(shutdownContext); err != nil {
		t.Fatalf("shutdown observability: %v", err)
	}
	select {
	case <-traceReceived:
	default:
		t.Fatal("fake OTLP collector received no traces")
	}
	select {
	case <-metricsReceived:
	default:
		t.Fatal("fake OTLP collector received no metrics")
	}
}

func TestProvideObservability_DisablesExportersWithoutEndpoint(t *testing.T) {
	restoreObservabilityGlobals(t)
	runtime, _, err := provideObservability(config.Config{LogLevel: "INFO", TraceSampleRatio: 1, MetricExportInterval: time.Second})
	if err != nil {
		t.Fatalf("provideObservability() error = %v", err)
	}
	if runtime.httpNotFoundHandler == nil || runtime.httpMethodNotAllowedHandler == nil {
		t.Fatal("fallback observability handlers are nil")
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), telemetryShutdownTimeout)
	defer cancel()
	if err := runtime.shutdown(shutdownContext); err != nil {
		t.Fatalf("shutdown observability: %v", err)
	}
}

func restoreObservabilityGlobals(t *testing.T) {
	t.Helper()
	previousLogger := slog.Default()
	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()
	previousPropagator := otel.GetTextMapPropagator()
	previousErrorHandler := otel.GetErrorHandler()
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		otel.SetTracerProvider(previousTracerProvider)
		otel.SetMeterProvider(previousMeterProvider)
		otel.SetTextMapPropagator(previousPropagator)
		otel.SetErrorHandler(previousErrorHandler)
	})
}

func assertServerMetrics(t *testing.T, reader *sdkmetric.ManualReader, operation string, code int, reason string) {
	t.Helper()
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &collected); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	foundCounter, foundDuration := false, false
	for _, scope := range collected.ScopeMetrics {
		for _, current := range scope.Metrics {
			switch data := current.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range data.DataPoints {
					if attributeValue(point.Attributes, "operation") == operation {
						foundCounter = point.Value == 1 && point.Attributes.Len() == 4 && attributeValue(point.Attributes, "transport") != "" && attributeValue(point.Attributes, "code") == int64(code) && attributeValue(point.Attributes, "reason") == reason
					}
				}
			case metricdata.Histogram[float64]:
				for _, point := range data.DataPoints {
					if attributeValue(point.Attributes, "operation") == operation {
						_, hasCode := point.Attributes.Value(attribute.Key("code"))
						_, hasReason := point.Attributes.Value(attribute.Key("reason"))
						foundDuration = point.Count == 1 && point.Attributes.Len() == 2 && !hasCode && !hasReason
					}
				}
			}
		}
	}
	if !foundCounter || !foundDuration {
		t.Fatalf("metrics missing or labels invalid: counter=%v duration=%v data=%#v", foundCounter, foundDuration, collected)
	}
}

func attributeValue(set attribute.Set, key string) any {
	value, found := set.Value(attribute.Key(key))
	if !found {
		return nil
	}
	return value.AsInterface()
}

func assertSpanRedacted(t *testing.T, span sdktrace.ReadOnlySpan, forbidden ...string) {
	t.Helper()
	for _, current := range span.Attributes() {
		encoded := string(current.Key) + "=" + current.Value.Emit()
		for _, value := range forbidden {
			if strings.Contains(encoded, value) {
				t.Fatalf("span attribute contains %q: %s", value, encoded)
			}
		}
	}
}

func TestObservableOperationRegistry_BoundsUnknownInput(t *testing.T) {
	registry := newObservableOperationRegistry()
	registry.register("http", []string{"/v1/users/me/profile"})
	if got := registry.normalize("http", "/v1/users/me/profile"); got != "/v1/users/me/profile" {
		t.Fatalf("known operation = %q", got)
	}
	if got := registry.normalize("http", "/attacker/controlled/value"); got != "http.unmatched" {
		t.Fatalf("unknown operation = %q", got)
	}
}

func TestParseSlogLevel(t *testing.T) {
	for _, value := range []string{"", "DEBUG", "INFO", "WARN", "ERROR"} {
		if _, err := parseSlogLevel(value); err != nil {
			t.Fatalf("parseSlogLevel(%q): %v", value, err)
		}
	}
	if _, err := parseSlogLevel("TRACE"); err == nil {
		t.Fatal("parseSlogLevel(TRACE) error = nil")
	}
}
