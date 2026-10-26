package aitpverifier

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The release workflow takes its notes from CHANGELOG.md and fails a tag
// that is not "v" + Version, so both must agree before a tag is cut.
func TestVersion(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(Version) {
		t.Fatalf("Version %q is not MAJOR.MINOR.PATCH", Version)
	}
	b, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\n## ["+Version+"]") {
		t.Fatalf("CHANGELOG.md has no section for %s", Version)
	}
}
