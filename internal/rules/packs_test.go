package rules

import (
	"strings"
	"testing"
)

func TestRegistryIsPinned(t *testing.T) {
	t.Parallel()
	if len(Packs) == 0 {
		t.Fatal("registry is empty")
	}
	for _, p := range Packs {
		if !p.Pinned() {
			t.Errorf("%s is not pinned to a commit and tarball digest; run make rule-packs", p.Name)
		}
		if !strings.HasSuffix(p.TarballURL(), "/tar.gz/"+p.Commit) {
			t.Errorf("%s tarball URL does not name its commit: %s", p.Name, p.TarballURL())
		}
	}
	for _, name := range []string{"opengrep", "amplify", "aikido"} {
		if _, ok := Lookup(name); !ok {
			t.Errorf("registry lacks %s", name)
		}
	}
}

func TestParsePacksRejectsInvalidRegistries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data string
	}{
		{name: "not JSON", data: `{`},
		{name: "repeated name", data: `[{"name":"a","repo":"o/r","license":"MIT","rule_dirs":["r"]},{"name":"a","repo":"o/r","license":"MIT","rule_dirs":["r"]}]`},
		{name: "reserved name", data: `[{"name":"starter","repo":"o/r","license":"MIT","rule_dirs":["r"]}]`},
		{name: "invalid name", data: `[{"name":"A/b","repo":"o/r","license":"MIT","rule_dirs":["r"]}]`},
		{name: "no license", data: `[{"name":"a","repo":"o/r","rule_dirs":["r"]}]`},
		{name: "no rule dirs", data: `[{"name":"a","repo":"o/r","license":"MIT"}]`},
		{name: "profile without dir", data: `[{"name":"a","repo":"o/r","license":"MIT","rule_dirs":["r"],"default_profile":"d"}]`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParsePacks([]byte(tt.data)); err == nil {
				t.Fatal("invalid registry accepted")
			}
		})
	}
}
