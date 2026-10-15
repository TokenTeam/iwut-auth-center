package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	d "iwut-auth-center/internal/oauth/domain"
)

const applicationUserStorageMessageLimit = 16 * 1024

type storageBatchGetRequest struct {
	Keys []string `json:"keys"`
}

type storageMutationRequest struct {
	ExpectedRevision *int64 `json:"expectedRevision"`
	Mutations        []struct {
		Key    string  `json:"key"`
		Action string  `json:"action"`
		Value  *string `json:"value,omitempty"`
	} `json:"mutations"`
}

func (h *OAuthHTTP) applicationUserStorage(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !h.rate("storage-ip:"+host, oauthLimit(h.IPPerMinute, 120)) {
		w.Header().Set("Retry-After", "60")
		storageHTTPRateError(w)
		return
	}
	if r.Method == http.MethodOptions {
		h.applicationUserStoragePreflight(w, r)
		return
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.ForceQuery {
		storageHTTPError(w, d.ErrRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		storageHTTPUnsupportedMedia(w)
		return
	}
	rawToken, err := oauthBearer(r)
	if err != nil {
		storageHTTPError(w, err)
		return
	}
	clientID, accessErr := h.Service.AccessClient(r.Context(), rawToken)
	if accessErr != nil {
		storageHTTPError(w, accessErr)
		return
	}
	digest := sha256.Sum256([]byte(rawToken))
	if !h.rate("storage-client:"+clientID, oauthLimit(h.ClientPerMinute, 300)) || !h.rate("storage-token:"+string(digest[:]), 120) {
		w.Header().Set("Retry-After", "60")
		storageHTTPRateError(w)
		return
	}
	if r.Header.Get("Origin") != "" {
		if !h.cors(w, r, clientID) {
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, applicationUserStorageMessageLimit+1))
	if err != nil {
		storageHTTPError(w, d.ErrRequest)
		return
	}
	if len(body) > applicationUserStorageMessageLimit {
		storageHTTPError(w, d.ErrStorageLimit)
		return
	}
	switch r.URL.Path {
	case "/v1/application-user-storage:batchGet":
		var request storageBatchGetRequest
		if decodeStorageJSON(body, &request) != nil {
			storageHTTPError(w, d.ErrRequest)
			return
		}
		out, callErr := h.Service.BatchGetApplicationUserStorage(r.Context(), rawToken, request.Keys)
		if callErr != nil {
			storageHTTPError(w, callErr)
			return
		}
		entries := make([]map[string]string, 0, len(out.Entries))
		for _, entry := range out.Entries {
			entries = append(entries, map[string]string{"key": entry.Key, "value": entry.Value})
		}
		response := map[string]any{"entries": entries, "missingKeys": out.MissingKeys, "revision": out.Revision}
		if !out.UpdatedAt.IsZero() {
			response["updatedAt"] = out.UpdatedAt.UTC().Format(time.RFC3339Nano)
		}
		oauthJSON(w, http.StatusOK, response)
	case "/v1/application-user-storage:mutate":
		var request storageMutationRequest
		if decodeStorageJSON(body, &request) != nil || request.ExpectedRevision == nil {
			storageHTTPError(w, d.ErrRequest)
			return
		}
		mutations := make([]d.StorageMutation, len(request.Mutations))
		for i, mutation := range request.Mutations {
			if mutation.Action == "PUT" && mutation.Value == nil || mutation.Action == "DELETE" && mutation.Value != nil {
				storageHTTPError(w, d.ErrRequest)
				return
			}
			mutations[i] = d.StorageMutation{Key: mutation.Key, Action: mutation.Action}
			if mutation.Value != nil {
				mutations[i].Value = *mutation.Value
			}
		}
		out, callErr := h.Service.MutateApplicationUserStorage(r.Context(), rawToken, *request.ExpectedRevision, mutations)
		if callErr != nil {
			storageHTTPError(w, callErr)
			return
		}
		response := map[string]any{"revision": out.Revision, "changed": out.Changed}
		if !out.UpdatedAt.IsZero() {
			response["updatedAt"] = out.UpdatedAt.UTC().Format(time.RFC3339Nano)
		}
		oauthJSON(w, http.StatusOK, response)
	default:
		http.NotFound(w, r)
	}
}

func (h *OAuthHTTP) applicationUserStoragePreflight(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.Header.Get("Access-Control-Request-Method") != http.MethodPost {
		storageHTTPError(w, d.ErrRequest)
		return
	}
	for _, header := range strings.Split(strings.ToLower(r.Header.Get("Access-Control-Request-Headers")), ",") {
		switch strings.TrimSpace(header) {
		case "", "authorization", "content-type":
		default:
			storageHTTPError(w, d.ErrRequest)
			return
		}
	}
	if !h.cors(w, r, "") {
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "authorization, content-type")
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
	w.WriteHeader(http.StatusNoContent)
}

func decodeStorageJSON(data []byte, target any) error {
	if err := rejectDuplicateStorageJSONNames(data); err != nil {
		return err
	}
	if err := strictJSONObject(data, target); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return d.ErrRequest
	}
	return nil
}

func rejectDuplicateStorageJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanStorageJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return d.ErrRequest
	}
	return nil
}

func scanStorageJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, keyOK := keyToken.(string)
			if !keyOK {
				return d.ErrRequest
			}
			if _, duplicate := seen[key]; duplicate {
				return d.ErrRequest
			}
			seen[key] = struct{}{}
			if err = scanStorageJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err = scanStorageJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return d.ErrRequest
	}
	closing, err := decoder.Token()
	if err != nil || closing != delimiter+2 {
		return d.ErrRequest
	}
	return nil
}

func storageHTTPRateError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": "APPLICATION_USER_STORAGE_RATE_LIMITED"})
}

func storageHTTPUnsupportedMedia(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnsupportedMediaType)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": "INVALID_APPLICATION_USER_STORAGE_REQUEST"})
}

func storageHTTPError(w http.ResponseWriter, err error) {
	status, reason := http.StatusServiceUnavailable, "APPLICATION_USER_STORAGE_UNAVAILABLE"
	response := map[string]any{}
	switch {
	case errors.Is(err, d.ErrRequest):
		status, reason = http.StatusBadRequest, "INVALID_APPLICATION_USER_STORAGE_REQUEST"
	case errors.Is(err, d.ErrToken), errors.Is(err, d.ErrGrant):
		status, reason = http.StatusUnauthorized, "APPLICATION_USER_STORAGE_TOKEN_INVALID"
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	case errors.Is(err, d.ErrInsufficient), errors.Is(err, d.ErrScope):
		status, reason = http.StatusForbidden, "APPLICATION_USER_STORAGE_SCOPE_REQUIRED"
	case errors.Is(err, d.ErrStorageConflict):
		status, reason = http.StatusConflict, "APPLICATION_USER_STORAGE_CONFLICT"
		var conflict d.StorageConflict
		if errors.As(err, &conflict) && conflict.MinimumRevision >= 0 {
			response["minimumRevision"] = conflict.MinimumRevision
		}
	case errors.Is(err, d.ErrStorageLimit):
		status, reason = http.StatusRequestEntityTooLarge, "APPLICATION_USER_STORAGE_LIMIT_EXCEEDED"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	response["reason"] = reason
	_ = json.NewEncoder(w).Encode(response)
}
