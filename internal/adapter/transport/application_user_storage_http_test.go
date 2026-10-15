package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	d "iwut-auth-center/internal/oauth/domain"
)

func TestDecodeApplicationUserStorageJSONIsStrictAtEveryDepth(t *testing.T) {
	tests := map[string]string{
		"top-level duplicate": `{"expectedRevision":0,"expectedRevision":1,"mutations":[{"key":"theme","action":"PUT","value":"dark"}]}`,
		"nested duplicate":    `{"expectedRevision":0,"mutations":[{"key":"theme","key":"locale","action":"PUT","value":"dark"}]}`,
		"nested unknown":      `{"expectedRevision":0,"mutations":[{"key":"theme","action":"PUT","value":"dark","unknown":true}]}`,
		"trailing value":      `{"expectedRevision":0,"mutations":[]} {}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			var request storageMutationRequest
			if err := decodeStorageJSON([]byte(body), &request); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
	var request storageMutationRequest
	if err := decodeStorageJSON([]byte(`{"expectedRevision":0,"mutations":[{"key":"theme","action":"PUT","value":"dark"}]}`), &request); err != nil {
		t.Fatalf("valid JSON rejected: %v", err)
	}
}

func TestApplicationUserStorageConflictIncludesRevisionFloor(t *testing.T) {
	recorder := httptest.NewRecorder()
	storageHTTPError(recorder, d.StorageConflict{MinimumRevision: 7})
	if recorder.Code != http.StatusConflict || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d, headers=%v", recorder.Code, recorder.Header())
	}
	var response struct {
		Reason          string `json:"reason"`
		MinimumRevision int64  `json:"minimumRevision"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.Reason != "APPLICATION_USER_STORAGE_CONFLICT" || response.MinimumRevision != 7 {
		t.Fatalf("body = %s, error = %v", recorder.Body.String(), err)
	}
}

func TestApplicationUserStorageUnsupportedMedia(t *testing.T) {
	recorder := httptest.NewRecorder()
	storageHTTPUnsupportedMedia(recorder)
	if recorder.Code != http.StatusUnsupportedMediaType || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d, headers=%v", recorder.Code, recorder.Header())
	}
}
