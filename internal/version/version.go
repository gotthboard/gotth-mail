package version

import (
	"fmt"
	"strconv"
	"strings"
)

var Version = "dev"

// Validate admits only development identity or the owner-approved 1.0 release
// line. Published versions before stable 1.0 are alpha or beta builds.
func Validate(value string) error {
	if value == "dev" || value == "1.0.0" {
		return nil
	}
	for _, prefix := range []string{"1.0.0-alpha.", "1.0.0-beta."} {
		if strings.HasPrefix(value, prefix) {
			number := strings.TrimPrefix(value, prefix)
			if number == "" || number[0] == '0' {
				break
			}
			sequence, err := strconv.ParseUint(number, 10, 31)
			if err == nil && sequence > 0 {
				return nil
			}
			break
		}
	}
	return fmt.Errorf("invalid GOTTH Mail release version %q", value)
}

// Tag returns the immutable Git tag for an admitted non-development build.
func Tag(value string) (string, error) {
	if err := Validate(value); err != nil {
		return "", err
	}
	if value == "dev" {
		return "", fmt.Errorf("development build has no release tag")
	}
	return "v" + value, nil
}

// Stage returns the release state represented by a valid build identity.
func Stage(value string) (string, error) {
	if err := Validate(value); err != nil {
		return "", err
	}
	switch {
	case value == "dev":
		return "development", nil
	case strings.Contains(value, "-alpha."):
		return "alpha", nil
	case strings.Contains(value, "-beta."):
		return "beta", nil
	default:
		return "stable", nil
	}
}
