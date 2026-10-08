package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

func TestHTTPHealthEndpoints(t *testing.T) {
	ready := true
	server := khttp.NewServer()
	registerHTTPHealth(server, func(context.Context) error {
		if !ready {
			return errors.New("mongodb://secret-host unavailable")
		}
		return nil
	}, time.Second, nil)
	host := httptest.NewServer(server)
	t.Cleanup(host.Close)

	assertProbe := func(method, path string, wantStatus int, wantBody string) {
		t.Helper()
		request, _ := http.NewRequest(method, host.URL+path, nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != wantStatus || string(body) != wantBody || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s = status %d body %q cache %q", method, path, response.StatusCode, body, response.Header.Get("Cache-Control"))
		}
	}

	assertProbe(http.MethodGet, "/livez", http.StatusOK, "ok\n")
	assertProbe(http.MethodHead, "/livez", http.StatusOK, "")
	assertProbe(http.MethodGet, "/readyz", http.StatusOK, "ok\n")
	ready = false
	assertProbe(http.MethodGet, "/readyz", http.StatusServiceUnavailable, "not ready\n")
	request, _ := http.NewRequest(http.MethodPost, host.URL+"/readyz", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /readyz = %v, %v", response, err)
	}
	_ = response.Body.Close()
}
