package rules

import (
	"slices"
	"testing"
)

func TestParseSpecs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		values []string
		want   []Spec
	}{
		{name: "default is starter", values: nil, want: []Spec{{Kind: StarterSpec}}},
		{name: "pack uses its default profile", values: []string{"amplify"}, want: []Spec{{Kind: PackSpec, Name: "amplify"}}},
		{name: "unknown pack is resolved at scan time", values: []string{"notinstalled"}, want: []Spec{{Kind: PackSpec, Name: "notinstalled"}}},
		{name: "explicit profile", values: []string{"amplify:security-audit"}, want: []Spec{{Kind: PackSpec, Name: "amplify", Profile: "security-audit"}}},
		{name: "directory profile", values: []string{"./team:audit"}, want: []Spec{{Kind: PathSpec, Path: "./team", Profile: "audit"}}},
		{name: "absolute directory profile", values: []string{"/srv/rules/team:audit"}, want: []Spec{{Kind: PathSpec, Path: "/srv/rules/team", Profile: "audit"}}},
		{name: "yaml file", values: []string{"team.yaml"}, want: []Spec{{Kind: PathSpec, Path: "team.yaml"}}},
		{name: "yml file", values: []string{"team.yml"}, want: []Spec{{Kind: PathSpec, Path: "team.yml"}}},
		{name: "path without extension", values: []string{"rules/custom"}, want: []Spec{{Kind: PathSpec, Path: "rules/custom"}}},
		{name: "path that looks like a pack", values: []string{"./amplify"}, want: []Spec{{Kind: PathSpec, Path: "./amplify"}}},
		{name: "several", values: []string{"starter", " amplify:secrets", "my.yml"}, want: []Spec{
			{Kind: StarterSpec}, {Kind: PackSpec, Name: "amplify", Profile: "secrets"}, {Kind: PathSpec, Path: "my.yml"},
		}},
		{name: "local profile file", values: []string{"opengrep:./security.list"}, want: []Spec{{Kind: PackSpec, Name: "opengrep", ProfileFile: "./security.list"}}},
		{name: "absolute profile file", values: []string{"opengrep:/tmp/security.list"}, want: []Spec{{Kind: PackSpec, Name: "opengrep", ProfileFile: "/tmp/security.list"}}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseSpecs(tt.values)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("ParseSpecs(%q) = %+v, want %+v", tt.values, got, tt.want)
			}
		})
	}
}

func TestParseSpecRejects(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "-x", "amplify:", "amplify:..", "amplify:a b", "starter:default"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if spec, err := ParseSpec(value); err == nil {
				t.Fatalf("accepted %q as %+v", value, spec)
			}
		})
	}
}
