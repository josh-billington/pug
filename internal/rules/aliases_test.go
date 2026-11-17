package rules

import (
	"strings"
	"testing"
)

func TestParseInstallSpec(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
		want  InstallSpec
	}{
		{name: "opengrep alias", value: "opengrep", want: InstallSpec{Name: "opengrep", URL: "https://github.com/opengrep/opengrep-rules.git"}},
		{name: "amplify alias", value: "amplify", want: InstallSpec{Name: "amplify", URL: "https://github.com/amplify-security/opengrep-rules.git"}},
		{name: "aikido alias", value: "aikido", want: InstallSpec{Name: "aikido", URL: "https://github.com/AikidoSec/opengrep-rules.git"}},
		{name: "alias with commit", value: "amplify@" + strings.Repeat("AB", 20), want: InstallSpec{Name: "amplify", URL: "https://github.com/amplify-security/opengrep-rules.git", Commit: strings.Repeat("ab", 20)}},
		{name: "sha256 commit", value: "amplify@" + strings.Repeat("c", 64), want: InstallSpec{Name: "amplify", URL: "https://github.com/amplify-security/opengrep-rules.git", Commit: strings.Repeat("c", 64)}},
		{name: "github shorthand", value: "github.com/trailofbits/semgrep-rules", want: InstallSpec{Name: "semgrep-rules", URL: "https://github.com/trailofbits/semgrep-rules"}},
		{name: "https", value: "https://example.com/team/my.rules.git@" + strings.Repeat("a", 40), want: InstallSpec{Name: "my.rules", URL: "https://example.com/team/my.rules.git", Commit: strings.Repeat("a", 40)}},
		{name: "local mirror", value: "file:///tmp/my-rules", want: InstallSpec{Name: "my-rules", URL: "file:///tmp/my-rules"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseInstallSpec(tt.value)
			if err != nil || got != tt.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestParseInstallSpecRejects(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"", "-x", "--upload-pack=evil", "unknown", "amplify@", "amplify@-x", "amplify@HEAD", "amplify@abc", "amplify@abcdef123456", "amplify@aabb;echo",
		"http://example.com/rules", "ssh://example.com/rules", "https://example.com/", "https://example.com/-rules",
		"https://example.com/starter", "https://example.com/myrules.yaml.git", "https://example.com/myrules.yml", "https://example.com/amplify", "https://example.com/aikido.git", "https://-example.com/rules",
		"https://user:pass@example.com/rules", "https://user:pass@example.com/rules@" + strings.Repeat("a", 40), "https://example.com/rules?q=1", "https://example.com/rules#branch", "file://host/tmp/rules",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if got, err := ParseInstallSpec(value); err == nil {
				t.Fatalf("accepted %q as %+v", value, got)
			}
		})
	}
}
