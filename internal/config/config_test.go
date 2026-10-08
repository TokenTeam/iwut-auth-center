package config

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

var testServiceCallers = base64.StdEncoding.EncodeToString([]byte(`{"iwut-app-center":{"status":"ACTIVE","keys":{"kid-1":{"publicKeyPemB64":"cGVt"}},"permissions":["auth.scope-catalog.read"],"systemPrincipalPurposes":[]}}`))

func withRequiredServiceCallers(lookup LookupEnv) LookupEnv {
	return func(key string) (string, bool) {
		if key == ServiceCallersEnv {
			return testServiceCallers, true
		}
		if lookup == nil {
			return "", false
		}
		return lookup(key)
	}
}

func TestLoadUsesDefaults(t *testing.T) {
	configuration, err := Load(withRequiredServiceCallers(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.GRPCAddr != DefaultGRPCAddr {
		t.Fatalf("GRPCAddr = %q, want %q", configuration.GRPCAddr, DefaultGRPCAddr)
	}
	if configuration.MongoURI != DefaultMongoURI {
		t.Fatalf("MongoURI = %q, want %q", configuration.MongoURI, DefaultMongoURI)
	}
	if configuration.MongoDatabase != DefaultMongoDatabase {
		t.Fatalf("MongoDatabase = %q, want %q", configuration.MongoDatabase, DefaultMongoDatabase)
	}
	if configuration.LogLevel != DefaultLogLevel || configuration.TraceSampleRatio != DefaultTraceSampleRatio || configuration.MetricExportInterval != DefaultMetricExportInterval {
		t.Fatalf("observability defaults = (%q, %v, %v)", configuration.LogLevel, configuration.TraceSampleRatio, configuration.MetricExportInterval)
	}
}

func TestLoadObservabilityConfiguration(t *testing.T) {
	configuration, err := Load(withRequiredServiceCallers(func(key string) (string, bool) {
		values := map[string]string{
			LogLevelEnv: " debug ", OTLPGRPCEndpointEnv: "127.0.0.1:4317", OTLPInsecureEnv: "true",
			TraceSampleRatioEnv: "0.75", MetricExportIntervalEnv: "5s",
		}
		value, found := values[key]
		return value, found
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.LogLevel != "DEBUG" || configuration.OTLPGRPCEndpoint != "127.0.0.1:4317" || !configuration.OTLPInsecure || configuration.TraceSampleRatio != 0.75 || configuration.MetricExportInterval != 5*time.Second {
		t.Fatalf("observability config = %+v", configuration)
	}
}

func TestLoadAcceptsExplicitGRPCAddress(t *testing.T) {
	configuration, err := Load(withRequiredServiceCallers(func(key string) (string, bool) {
		if key == GRPCAddrEnv {
			return " 127.0.0.1:19000 ", true
		}
		return "", false
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.GRPCAddr != "127.0.0.1:19000" {
		t.Fatalf("GRPCAddr = %q", configuration.GRPCAddr)
	}
}

func TestLoadAcceptsExplicitMongoConfiguration(t *testing.T) {
	configuration, err := Load(withRequiredServiceCallers(func(key string) (string, bool) {
		switch key {
		case MongoURIEnv:
			return " mongodb://mongo:27017 ", true
		case MongoDatabaseEnv:
			return " auth_test ", true
		default:
			return "", false
		}
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if configuration.MongoURI != "mongodb://mongo:27017" || configuration.MongoDatabase != "auth_test" {
		t.Fatalf("mongo configuration = (%q, %q)", configuration.MongoURI, configuration.MongoDatabase)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		lookup LookupEnv
	}{
		{name: "nil lookup", lookup: nil},
		{name: "missing callers", lookup: func(string) (string, bool) { return "", false }},
		{name: "empty explicit address", lookup: withRequiredServiceCallers(func(key string) (string, bool) {
			if key == GRPCAddrEnv {
				return " ", true
			}
			return "", false
		})},
		{name: "empty explicit mongo URI", lookup: withRequiredServiceCallers(func(key string) (string, bool) {
			if key == MongoURIEnv {
				return " ", true
			}
			return "", false
		})},
		{name: "empty explicit mongo database", lookup: withRequiredServiceCallers(func(key string) (string, bool) {
			if key == MongoDatabaseEnv {
				return " ", true
			}
			return "", false
		})},
		{name: "invalid log level", lookup: observabilityLookup(LogLevelEnv, "trace")},
		{name: "invalid OTLP endpoint", lookup: observabilityLookup(OTLPGRPCEndpointEnv, "https://collector:4317")},
		{name: "insecure without endpoint", lookup: observabilityLookup(OTLPInsecureEnv, "true")},
		{name: "invalid insecure", lookup: observabilityLookup(OTLPInsecureEnv, "TRUE")},
		{name: "invalid sample ratio", lookup: observabilityLookup(TraceSampleRatioEnv, "1.01")},
		{name: "short export interval", lookup: observabilityLookup(MetricExportIntervalEnv, "999ms")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(test.lookup)
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("Load() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

func observabilityLookup(key, value string) LookupEnv {
	return withRequiredServiceCallers(func(candidate string) (string, bool) {
		if candidate == key {
			return value, true
		}
		return "", false
	})
}

func TestLoadHTTPAddress(t *testing.T) {
	for _, tc := range []struct {
		value   string
		set     bool
		want    string
		invalid bool
	}{
		{want: DefaultHTTPAddr}, {value: " 127.0.0.1:18000 ", set: true, want: "127.0.0.1:18000"}, {value: " ", set: true, invalid: true},
	} {
		c, err := Load(withRequiredServiceCallers(func(key string) (string, bool) {
			if key == HTTPAddrEnv {
				return tc.value, tc.set
			}
			return "", false
		}))
		if tc.invalid {
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("expected invalid HTTP address: %v", err)
			}
			continue
		}
		if err != nil || c.HTTPAddr != tc.want {
			t.Fatalf("HTTP address: %q, %v", c.HTTPAddr, err)
		}
	}
}
