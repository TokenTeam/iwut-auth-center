package util

func IsASCIIAlphaNumDashUnderscore(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '-' || b == '_' {
			continue
		}
		return false
	}
	return true
}
