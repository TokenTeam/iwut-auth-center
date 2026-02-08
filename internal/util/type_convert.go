package util

import (
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/protobuf/types/known/structpb"
)

func ConvertBSONValueToGOType(v any) (any, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case bson.DateTime:
		return t.Time(), nil
	case bson.ObjectID:
		return t.Hex(), nil
	case string:
		return t, nil
	case int32:
		return t, nil
	case int64:
		return t, nil
	case float64:
		return t, nil
	case bool:
		return t, nil
	default:
		// 若需要，可在此增加对 primitive.Decimal128、[]interface{}、bson.M 等的支持
		return nil, fmt.Errorf("unsupported bson type: %T", v)
	}
}

func StructToStringMap(s *structpb.Struct) (map[string]string, error) {
	if s == nil {
		return nil, nil
	}
	out := make(map[string]string, len(s.Fields))
	for k, v := range s.Fields {
		if v == nil {
			return nil, fmt.Errorf("unsupported Value kind: null, only string allowed")
		}
		switch kind := v.Kind.(type) {
		case *structpb.Value_StringValue:
			out[k] = kind.StringValue
		default:
			return nil, fmt.Errorf("unsupported Value kind: %T, only string allowed", kind)
		}
	}
	return out, nil
}

func StringMapToStructpbValueMap(m map[string]*string) (map[string]*structpb.Value, error) {
	if m == nil {
		return nil, nil
	}
	out := make(map[string]*structpb.Value, len(m))
	for k, v := range m {
		if v == nil {
			out[k] = structpb.NewNullValue()
		} else {
			out[k] = structpb.NewStringValue(*v)
		}
	}
	return out, nil
}
