package transport

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	scopecatalogv1 "iwut-auth-center/api/gen/go/auth_center/v1/scope_catalog"
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

func protoreflectName(value string) protoreflect.Name {
	return protoreflect.Name(value)
}
