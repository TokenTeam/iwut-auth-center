package transport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pb "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/managed_user_search"
)

func TestManagedUserSearchStrictJSONSelectors(t *testing.T) {
	for _, body := range []string{
		`{"authId":null,"email":"u@example.test"}`,
		`{"authId":"u","email":null}`,
		`{"authId":null}`,
		`{"email":"u@example.test","email":"other@example.test"}`,
		`{"authId":"u","auth_id":"other"}`,
		`{"authId":"u","permissions":[]}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/managed-users:search", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		err := authHTTPDecoder(16*1024)(req, &pb.SearchUsersRequest{})
		if err == nil {
			t.Fatal("malformed selectors accepted", body)
		}
		out := httptest.NewRecorder()
		authHTTPErrorEncoder(out, req, err)
		if out.Code != 400 || out.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal(out.Code, out.Body.String())
		}
	}
}
