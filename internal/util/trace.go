package util

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

func RequestIDFrom(ctx context.Context) string {
	spanCtx := trace.SpanContextFromContext(ctx)
	traceID := ""
	if spanCtx.HasTraceID() {
		traceID = spanCtx.TraceID().String()
	}
	return traceID
}
