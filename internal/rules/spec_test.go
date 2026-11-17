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
		want   []string
		kinds  []SpecKind
	}{
		{name: "default is starter", values: nil, want: []string{"starter"}, kinds: []SpecKind{StarterSpec}},
		{name: "pack uses its default profile", values: []string{"amplify"}, want: []string{"amplify:default"}, kinds: []SpecKind{PackSpec}},
		{name: "pack without profiles", values: []string{"opengrep"}, want: []string{"opengrep"}, kinds: []SpecKind{PackSpec}},
		{name: "explicit profile", values: []string{"amplify:security-audit"}, want: []string{"amplify:security-audit"}, kinds: []SpecKind{PackSpec}},
		{name: "yaml file", values: []string{"team.yaml"}, want: []string{"team.yaml"}, kinds: []SpecKind{FileSpec}},
		{name: "path without extension", values: []string{"rules/custom"}, want: []string{"rules/custom"}, kinds: []SpecKind{FileSpec}},
		{name: "path that looks like a pack", values: []string{"./amplify"}, want: []string{"./amplify"}, kinds: []SpecKind{FileSpec}},
		{name: "several", values: []string{"starter", " amplify:secrets", "my.yml"}, want: []string{"starter", "amplify:secrets", "my.yml"}, kinds: []SpecKind{StarterSpec, PackSpec, FileSpec}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			specs, err := ParseSpecs(tt.values)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			var kinds []SpecKind
			for _, spec := range specs {
				got = append(got, spec.String())
				kinds = append(kinds, spec.Kind)
			}
			if !slices.Equal(got, tt.want) || !slices.Equal(kinds, tt.kinds) {
				t.Fatalf("got %v %v, want %v %v", got, kinds, tt.want, tt.kinds)
			}
		})
	}
}

func TestParseSpecRejects(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", "unknown", "opengrep:default", "amplify:", "amplify:..", "amplify:a b", "starter:default"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if spec, err := ParseSpec(value); err == nil {
				t.Fatalf("accepted %q as %+v", value, spec)
			}
		})
	}
}
