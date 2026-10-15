package config

import (
	"fmt"
	"strconv"
)

const AcademicYearPolicyEndpointsEnabledEnv = "AUTH_ACADEMIC_YEAR_POLICY_ENDPOINTS_ENABLED"

type AcademicYearPolicy struct {
	ReadPerMinute  int
	WritePerMinute int
	MaxBuckets     int
}

func loadAcademicYearPolicy(lookup LookupEnv, user *UserEndpoints, issuance *IdentityIssuance) (*AcademicYearPolicy, error) {
	configuration := &AcademicYearPolicy{ReadPerMinute: 60, WritePerMinute: 10, MaxBuckets: 4096}
	enabled := false
	if raw, found := lookup(AcademicYearPolicyEndpointsEnabledEnv); found {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, AcademicYearPolicyEndpointsEnabledEnv)
		}
		enabled = value
	}
	for name, target := range map[string]*int{
		"AUTH_ACADEMIC_YEAR_POLICY_READ_PER_MINUTE":  &configuration.ReadPerMinute,
		"AUTH_ACADEMIC_YEAR_POLICY_WRITE_PER_MINUTE": &configuration.WritePerMinute,
		"AUTH_ACADEMIC_YEAR_POLICY_MAX_BUCKETS":      &configuration.MaxBuckets,
	} {
		if raw, found := lookup(name); found {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > 1000000 {
				return nil, fmt.Errorf("%w: invalid %s", ErrInvalidConfiguration, name)
			}
			*target = value
		}
	}
	if !enabled {
		return nil, nil
	}
	if user == nil || issuance == nil {
		return nil, fmt.Errorf("%w: academic year policy endpoints require user endpoints and identity issuance", ErrInvalidConfiguration)
	}
	return configuration, nil
}
