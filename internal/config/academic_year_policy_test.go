package config

import "testing"

func TestAcademicYearPolicyConfigurationIsDefaultOffAndBounded(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	configuration, err := loadAcademicYearPolicy(lookup, &UserEndpoints{}, &IdentityIssuance{})
	if err != nil || configuration != nil {
		t.Fatalf("default policy = %#v, %v", configuration, err)
	}
	environment := map[string]string{
		AcademicYearPolicyEndpointsEnabledEnv:        "true",
		"AUTH_ACADEMIC_YEAR_POLICY_READ_PER_MINUTE":  "7",
		"AUTH_ACADEMIC_YEAR_POLICY_WRITE_PER_MINUTE": "3",
		"AUTH_ACADEMIC_YEAR_POLICY_MAX_BUCKETS":      "99",
	}
	lookup = func(key string) (string, bool) { value, found := environment[key]; return value, found }
	if _, err = loadAcademicYearPolicy(lookup, nil, nil); err == nil {
		t.Fatal("enabled policy without user identity dependencies was accepted")
	}
	configuration, err = loadAcademicYearPolicy(lookup, &UserEndpoints{}, &IdentityIssuance{})
	if err != nil || configuration.ReadPerMinute != 7 || configuration.WritePerMinute != 3 || configuration.MaxBuckets != 99 {
		t.Fatalf("configured policy = %#v, %v", configuration, err)
	}
}
