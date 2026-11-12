package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/script_permission"
	"google.golang.org/protobuf/encoding/protowire"

	"iwut-auth-center/internal/scriptpermission/domain"
)

func TestScriptPermissionStrictInputs(t *testing.T) {
	for _, input := range []struct{ path, body string }{
		{"/v1/script-permissions:manage", `{"subjectAuthId":"user","permission":"app.script.review"}`},
		{"/v1/script-permissions:manage", `{"subjectAuthId":"user","actorAuthId":"admin"}`},
		{"/v1/script-permissions:manage", `{"subjectAuthId":"user","subject_auth_id":"other"}`},
		{"/v1/script-permissions:manage?actorAuthId=admin", `{}`},
	} {
		filter := authHTTPFilter(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if err := authHTTPDecoder(16*1024)(req, &pb.ManageScriptPermissionRequest{}); err != nil {
				authHTTPErrorEncoder(w, req, err)
				return
			}
			w.WriteHeader(200)
		}))
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, input.path, strings.NewReader(input.body))
		req.Header.Set("Content-Type", "application/json")
		filter.ServeHTTP(recorder, req)
		if recorder.Code != 400 || !strings.Contains(recorder.Body.String(), domain.ErrInvalid.Error()) || recorder.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal(recorder.Code, recorder.Body.String(), recorder.Header())
		}
	}
	subject := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "user")
	duplicate := protowire.AppendString(protowire.AppendTag(append([]byte{}, subject...), 1, protowire.BytesType), "other")
	truncatingEnum := protowire.AppendVarint(protowire.AppendTag(append([]byte{}, subject...), 2, protowire.VarintType), 1<<32|1)
	for _, data := range [][]byte{duplicate, truncatingEnum} {
		message := &pb.ManageScriptPermissionRequest{}
		if err := NewProfileStrictCodec().Unmarshal(data, message); err != nil || len(message.ProtoReflect().GetUnknown()) == 0 {
			t.Fatal("malformed wire was not marked", err)
		}
	}
}

func TestScriptPermissionHTTPConflictAndRateLimit(t *testing.T) {
	for err, code := range map[error]int{domain.ErrGrantBlocked: 409, domain.ErrExhausted: 409, domain.ErrConflict: 409, domain.ErrRate: 429} {
		recorder := httptest.NewRecorder()
		authHTTPErrorEncoder(recorder, httptest.NewRequest(http.MethodPost, "/v1/script-permissions:manage", nil), scriptPermissionStatus(err))
		if recorder.Code != code || !strings.Contains(recorder.Body.String(), err.Error()) {
			t.Fatal(err, recorder.Code, recorder.Body.String())
		}
	}
}
