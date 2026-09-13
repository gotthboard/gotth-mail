package version

import "testing"

func TestValidateReleaseLine(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"dev", "1.0.0-alpha.1", "1.0.0-alpha.27", "1.0.0-beta.1", "1.0.0-beta.14", "1.0.0"} {
		if err := Validate(value); err != nil {
			t.Errorf("Validate(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", "v1.0.0", "0.1.0", "1.0.0-alpha", "1.0.0-alpha.0", "1.0.0-alpha.01", "1.0.0-beta.0", "1.0.0-rc.1", "1.0.1", "2.0.0"} {
		if err := Validate(value); err == nil {
			t.Errorf("Validate(%q) succeeded", value)
		}
	}
}

func TestTag(t *testing.T) {
	t.Parallel()
	if got, err := Tag("1.0.0-beta.3"); err != nil || got != "v1.0.0-beta.3" {
		t.Fatalf("Tag() = (%q, %v)", got, err)
	}
	if _, err := Tag("dev"); err == nil {
		t.Fatal("development build produced a release tag")
	}
}
