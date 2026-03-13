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
	case bson.A:
		list := make([]any, 0, len(t))
		for _, v := range t {
			val, err := ConvertBSONValueToGOType(v)
			if err != nil {
				return nil, err
			}
			list = append(list, val)
		}
		return list, nil
	case bson.D:
		mp := make(map[string]any, len(t))
		for _, kv := range t {
			val, err := ConvertBSONValueToGOType(kv.Value)
			if err != nil {
				return nil, err
			}
			mp[kv.Key] = val
		}
		return mp, nil
	case bson.M:
		mp := make(map[string]any, len(t))
		for k, v := range t {
			val, err := ConvertBSONValueToGOType(v)
			if err != nil {
				return nil, err
			}
			mp[k] = val
		}
		return mp, nil
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

func StructValueToAny(value *structpb.Value) (any, int64, error) {
	if value == nil {
		return nil, 0, nil
	}
	switch value.GetKind().(type) {
	case *structpb.Value_NullValue:
		return nil, 0, nil
	case *structpb.Value_StringValue:
		str := value.GetStringValue()
		return str, int64(len(str)), nil
	case *structpb.Value_NumberValue:
		return value.GetNumberValue(), 8, nil
	case *structpb.Value_BoolValue:
		return value.GetBoolValue(), 1, nil
	case *structpb.Value_StructValue:
		m, n, err := StructToAnyMap(value.GetStructValue())
		return m, n, err
	case *structpb.Value_ListValue:
		list := make([]any, 0, len(value.GetListValue().Values))
		total := int64(0)
		for _, item := range value.GetListValue().Values {
			v, n, err := StructValueToAny(item)
			if err != nil {
				return nil, 0, err
			}
			total += n
			list = append(list, v) // 注意这里 append 值，不是 *any
		}
		return list, total, nil
	default:
		return nil, 0, fmt.Errorf("unsupported value kind: %T", value.GetKind())
	}
}
func StructToAnyMap(s *structpb.Struct) (map[string]any, int64, error) {
	ans := make(map[string]any, len(s.GetFields()))
	totalLength := int64(0)
	for key, value := range s.GetFields() {
		if value == nil {
			ans[key] = nil
			continue
		}
		convertedValue, subLength, err := StructValueToAny(value)
		if err != nil {
			return nil, 0, err
		}
		totalLength += int64(len(key))
		totalLength += subLength
		if !IsASCIIAlphaNumDashUnderscore(key) {
			return nil, 0, fmt.Errorf("invalid key: %s", key)
		}
		ans[key] = convertedValue
	}
	return ans, totalLength, nil
}

func BsonMToStringMap(m bson.M) (map[string]string, map[string]any, error) {
	if m == nil {
		return nil, nil, nil
	}
	out := make(map[string]string, len(m))
	notStringKeyValue := make(map[string]any, len(m))
	for k, v := range m {
		strVal, ok := v.(string)
		if !ok {
			notStringKeyValue[k] = v
		} else {
			out[k] = strVal
		}
	}
	return out, notStringKeyValue, nil
}
