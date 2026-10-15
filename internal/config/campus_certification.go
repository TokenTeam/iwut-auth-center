package config

// Campus is an ADD alias and shares its key, quotas and directory. The retired
// campus-only CODE_KEY is neither parsed nor a startup/migration gate.
func loadCampusCertification(lookup LookupEnv, user *UserEndpoints) (*EmailBinding, error) {
	return loadEmailCapability(lookup, user, "AUTH_CAMPUS_CERTIFICATION_ENABLED", "AUTH_EMAIL_BINDING_HMAC_KEY")
}
