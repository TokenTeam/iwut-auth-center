package transport

import (
	"context"
	"net/http"
	"time"

	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

const defaultReadinessTimeout = 2 * time.Second

func registerHTTPHealth(server *khttp.Server, readiness func(context.Context) error, timeout time.Duration, observe func(string, http.Handler) http.Handler) {
	livez := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeProbeResponse(writer, request, http.StatusOK, "ok\n")
	})
	readyz := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if timeout <= 0 {
			timeout = defaultReadinessTimeout
		}
		if readiness == nil {
			writeProbeResponse(writer, request, http.StatusServiceUnavailable, "not ready\n")
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), timeout)
		defer cancel()
		if err := readiness(ctx); err != nil {
			writeProbeResponse(writer, request, http.StatusServiceUnavailable, "not ready\n")
			return
		}
		writeProbeResponse(writer, request, http.StatusOK, "ok\n")
	})
	if observe != nil {
		livez = observe("http.health.livez", livez).ServeHTTP
		readyz = observe("http.health.readyz", readyz).ServeHTTP
	}
	server.HandleFunc("/livez", livez)
	server.HandleFunc("/readyz", readyz)
}

func writeProbeResponse(writer http.ResponseWriter, request *http.Request, status int, body string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = writer.Write([]byte(body))
	}
}
