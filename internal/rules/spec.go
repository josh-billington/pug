package rules

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const starterName = "starter"

// SpecKind says where a --rules value takes its rules from.
type SpecKind int

const (
	// StarterSpec is the small rule set embedded in Pug.
	StarterSpec SpecKind = iota
	// PackSpec is an installed rule pack, optionally narrowed to a profile.
	PackSpec
	// FileSpec is a local OpenGrep rules file.
	FileSpec
)

// Spec is one parsed --rules value.
type Spec struct {
	Kind SpecKind
	Pack Pack
	// Profile is empty for the pack's default profile, or every rule when the
	// pack has no profiles.
	Profile string
	Path    string
}

var profileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ParseSpecs parses --rules values. No values selects the starter rules.
func ParseSpecs(values []string) ([]Spec, error) {
	if len(values) == 0 {
		return []Spec{{Kind: StarterSpec}}, nil
	}
	specs := make([]Spec, 0, len(values))
	for _, value := range values {
		spec, err := ParseSpec(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// ParseSpec parses "starter", "<pack>", "<pack>:<profile>", or a file path.
// A value is a path when it ends in .yml or .yaml or contains a separator.
func ParseSpec(value string) (Spec, error) {
	if value == "" {
		return Spec{}, fmt.Errorf("empty rules value")
	}
	if ext := filepath.Ext(value); ext == ".yml" || ext == ".yaml" || strings.ContainsRune(value, '/') || strings.ContainsRune(value, filepath.Separator) {
		return Spec{Kind: FileSpec, Path: value}, nil
	}
	if value == starterName {
		return Spec{Kind: StarterSpec}, nil
	}
	name, profile, hasProfile := strings.Cut(value, ":")
	pack, ok := Lookup(name)
	if !ok {
		return Spec{}, fmt.Errorf("unknown rule pack %q; available: starter, %s, or a path to a .yml file", name, strings.Join(Names(), ", "))
	}
	if !hasProfile {
		return Spec{Kind: PackSpec, Pack: pack}, nil
	}
	if pack.ProfilesDir == "" {
		return Spec{}, fmt.Errorf("rule pack %s has no profiles; use --rules %s", name, name)
	}
	if !profileName.MatchString(profile) {
		return Spec{}, fmt.Errorf("invalid profile name %q", profile)
	}
	return Spec{Kind: PackSpec, Pack: pack, Profile: profile}, nil
}

// String is the canonical form of the spec, as recorded in reports.
func (s Spec) String() string {
	switch s.Kind {
	case PackSpec:
		if profile := s.profile(); profile != "" {
			return s.Pack.Name + ":" + profile
		}
		return s.Pack.Name
	case FileSpec:
		return s.Path
	default:
		return starterName
	}
}

// profile is the profile the spec selects, after applying the pack default.
func (s Spec) profile() string {
	if s.Profile != "" {
		return s.Profile
	}
	return s.Pack.DefaultProfile
}
