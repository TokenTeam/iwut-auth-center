package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestAssociationConfiguration(t *testing.T) {
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	valid := map[string]string{"AUTH_ASSOC_KEY_VERSION": "v2", "AUTH_ASSOC_ENCRYPT_KEY": key(1), "AUTH_ASSOC_LOOKUP_KEY": key(2)}
	load := func(m map[string]string) (Association, error) {
		return LoadAssociation(func(s string) (string, bool) { v, ok := m[s]; return v, ok })
	}
	if c, err := load(valid); err != nil || c.Previous != nil {
		t.Fatal("current-only", err)
	}
	for _, name := range []string{"missing-current", "partial-previous", "same-purpose-key", "noncanonical-base64", "same-version", "reuse-across-generation", "invalid-version"} {
		t.Run(name, func(t *testing.T) {
			m := map[string]string{}
			for k, v := range valid {
				m[k] = v
			}
			switch name {
			case "missing-current":
				delete(m, "AUTH_ASSOC_KEY_VERSION")
			case "partial-previous":
				m["AUTH_ASSOC_PREVIOUS_KEY_VERSION"] = "v1"
			case "same-purpose-key":
				m["AUTH_ASSOC_LOOKUP_KEY"] = key(1)
			case "noncanonical-base64":
				m["AUTH_ASSOC_ENCRYPT_KEY"] += "\n"
			case "invalid-version":
				m["AUTH_ASSOC_KEY_VERSION"] = "v 2"
			default:
				m["AUTH_ASSOC_PREVIOUS_KEY_VERSION"] = "v1"
				m["AUTH_ASSOC_PREVIOUS_ENCRYPT_KEY"] = key(3)
				m["AUTH_ASSOC_PREVIOUS_LOOKUP_KEY"] = key(4)
				if name == "same-version" {
					m["AUTH_ASSOC_PREVIOUS_KEY_VERSION"] = "v2"
				} else {
					m["AUTH_ASSOC_PREVIOUS_LOOKUP_KEY"] = key(1)
				}
			}
			if _, err := load(m); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatal("invalid config accepted", err)
			}
		})
	}
	valid["AUTH_ASSOC_PREVIOUS_KEY_VERSION"] = "v1"
	valid["AUTH_ASSOC_PREVIOUS_ENCRYPT_KEY"] = key(3)
	valid["AUTH_ASSOC_PREVIOUS_LOOKUP_KEY"] = key(4)
	if c, err := load(valid); err != nil || c.Previous == nil || c.Previous.Version != "v1" {
		t.Fatal("rotation", err)
	}
}
