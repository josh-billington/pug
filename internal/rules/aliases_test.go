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
		{name: "alias", value: "amplify", want: InstallSpec{Name: "amplify", URL: Aliases["amplify"]}},
		{name: "alias with commit", value: "amplify@ABCDEF12", want: InstallSpec{Name: "amplify", URL: Aliases["amplify"], Commit: "abcdef12"}},
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
	for _, name := range []string{"opengrep", "amplify", "aikido"} {
		if _, err := ParseInstallSpec(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseInstallSpecRejects(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"", "-x", "--upload-pack=evil", "unknown", "amplify@", "amplify@-x", "amplify@HEAD", "amplify@abc", "amplify@aabb;echo",
		"http://example.com/rules", "ssh://example.com/rules", "https://example.com/", "https://example.com/-rules",
		"https://example.com/starter", "https://example.com/amplify", "https://example.com/aikido.git", "https://-example.com/rules",
		"https://user:pass@example.com/rules", "https://example.com/rules?q=1", "https://example.com/rules#branch", "file://host/tmp/rules",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if got, err := ParseInstallSpec(value); err == nil {
				t.Fatalf("accepted %q as %+v", value, got)
			}
		})
	}
}
