package mongo

import (
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// A lifecycle state and its revision form one authoritative record. Missing or
// coerced numeric fields must never make a corrupt state usable for issuance.
func validDeveloperLifecycle(raw bson.Raw) bool {
	if !identityFields(raw, map[string]bson.Type{"developerRevision": bson.TypeInt64}) {
		return false
	}
	revision := raw.Lookup("developerRevision").Int64()
	status := raw.Lookup("developerStatus")
	if status.Type == bson.TypeNull {
		return revision == 0
	}
	if status.Type != bson.TypeString || revision <= 0 {
		return false
	}
	switch status.StringValue() {
	case "PENDING", "APPROVED", "REJECTED", "SUSPENDED", "WITHDRAWN":
		return true
	default:
		return false
	}
}

// Closed accounts carry only a permanent minimal tombstone, never developer or
// permission fields. Readers must not attempt to repair it or add a write fence.
func validClosedPrincipal(raw bson.Raw) bool {
	if !identityFields(raw, map[string]bson.Type{"authId": bson.TypeString, "principalType": bson.TypeString, "accountStatus": bson.TypeString, "accountRevision": bson.TypeInt64, "terminatedAt": bson.TypeDateTime, "closureOperationId": bson.TypeString}) || raw.Lookup("authId").StringValue() == "" || raw.Lookup("principalType").StringValue() != "USER" || raw.Lookup("accountStatus").StringValue() != "CLOSED" || raw.Lookup("accountRevision").Int64() < 2 || raw.Lookup("terminatedAt").DateTime() <= 0 {
		return false
	}
	operation := raw.Lookup("closureOperationId").StringValue()
	id, err := uuid.Parse(operation)
	if err != nil || id.Version() != 4 || id.Variant() != uuid.RFC4122 || id.String() != operation {
		return false
	}
	elements, err := raw.Elements()
	if err != nil {
		return false
	}
	for _, element := range elements {
		switch element.Key() {
		case "_id", "authId", "principalType", "accountStatus", "accountRevision", "terminatedAt", "closureOperationId":
		default:
			return false
		}
	}
	return true
}
