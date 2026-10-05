package transport

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	developerstatusv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/developer_status"
	scopecatalogv1 "github.com/TokenTeam/iwut-api-proto/gen/go/auth_center/v1/scope_catalog"
)

func TestScopeCatalogContractMatchesPlatformV1(t *testing.T) {
	if got, want := scopecatalogv1.ScopeCatalog_GetScopeCatalogSnapshot_FullMethodName,
		"/auth_center.v1.scope_catalog.ScopeCatalog/GetScopeCatalogSnapshot"; got != want {
		t.Fatalf("full method = %q, want %q", got, want)
	}

	request := (&scopecatalogv1.GetScopeCatalogSnapshotRequest{}).ProtoReflect().Descriptor()
	if request.Fields().Len() != 0 {
		t.Fatalf("request field count = %d, want 0", request.Fields().Len())
	}

	response := (&scopecatalogv1.GetScopeCatalogSnapshotResponse{}).ProtoReflect().Descriptor()
	wantResponseFields := map[string]int32{"revision": 1, "generated_at": 2, "scopes": 3}
	if response.Fields().Len() != len(wantResponseFields) {
		t.Fatalf("response field count = %d, want %d", response.Fields().Len(), len(wantResponseFields))
	}
	for name, number := range wantResponseFields {
		field := response.Fields().ByName(protoreflectName(name))
		if field == nil || int32(field.Number()) != number {
			t.Fatalf("response field %s = %v", name, field)
		}
	}

	definition := (&scopecatalogv1.ScopeDefinition{}).ProtoReflect().Descriptor()
	if definition.Fields().Len() != 2 || int32(definition.Fields().ByName("name").Number()) != 1 || int32(definition.Fields().ByName("requestable").Number()) != 2 {
		t.Fatalf("ScopeDefinition descriptor = %v", definition.Fields())
	}
}

func TestDeveloperStatusContractMatchesPlatformV1(t *testing.T) {
	if got, want := developerstatusv1.DeveloperStatusDirectory_BatchGetDeveloperStatuses_FullMethodName,
		"/auth_center.v1.developer_status.DeveloperStatusDirectory/BatchGetDeveloperStatuses"; got != want {
		t.Fatalf("full method = %q, want %q", got, want)
	}

	request := (&developerstatusv1.BatchGetDeveloperStatusesRequest{}).ProtoReflect().Descriptor()
	if request.Fields().Len() != 1 || int32(request.Fields().ByName("auth_ids").Number()) != 1 || !request.Fields().ByName("auth_ids").IsList() {
		t.Fatalf("request descriptor = %v", request.Fields())
	}
	response := (&developerstatusv1.BatchGetDeveloperStatusesResponse{}).ProtoReflect().Descriptor()
	if response.Fields().Len() != 1 || int32(response.Fields().ByName("entries").Number()) != 1 || !response.Fields().ByName("entries").IsList() {
		t.Fatalf("response descriptor = %v", response.Fields())
	}
	entry := (&developerstatusv1.DeveloperStatusEntry{}).ProtoReflect().Descriptor()
	if entry.Fields().Len() != 3 || int32(entry.Fields().ByName("auth_id").Number()) != 1 || int32(entry.Fields().ByName("developer_status").Number()) != 2 {
		t.Fatalf("entry descriptor = %v", entry.Fields())
	}
}

func protoreflectName(value string) protoreflect.Name {
	return protoreflect.Name(value)
}
