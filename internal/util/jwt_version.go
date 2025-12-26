package util

func NextJWTVersion(version int) int {
	return (version + 1) % (1e9 + 7)
}
