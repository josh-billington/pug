package rules

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const starterName = "starter"

type SpecKind int

const (
	StarterSpec SpecKind = iota
	PackSpec
	PathSpec
)

type Spec struct {
	Kind        SpecKind
	Name        string
	Profile     string
	ProfileFile string
	Path        string
}

var profileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

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

func ParseSpec(value string) (Spec, error) {
	if value == "" || strings.HasPrefix(value, "-") {
		return Spec{}, fmt.Errorf("invalid rules value %q", value)
	}
	if value == starterName {
		return Spec{Kind: StarterSpec}, nil
	}
	name, profile := value, ""
	profileAt := strings.LastIndexByte(value, ':')
	hasProfile := profileAt >= len(filepath.VolumeName(value))
	if hasProfile {
		name, profile = value[:profileAt], value[profileAt+1:]
	}
	if hasProfile && profileFile(profile) {
		if !packName.MatchString(name) || name == starterName {
			return Spec{}, fmt.Errorf("invalid rule pack name %q", name)
		}
		return Spec{Kind: PackSpec, Name: name, ProfileFile: profile}, nil
	}
	if hasProfile && !profileName.MatchString(profile) {
		return Spec{}, fmt.Errorf("invalid profile name %q", profile)
	}
	ext := filepath.Ext(name)
	isPath := strings.ContainsAny(name, `/\`) || ext == ".yml" || ext == ".yaml"
	if isPath {
		return Spec{Kind: PathSpec, Path: name, Profile: profile}, nil
	}
	if !packName.MatchString(name) || name == starterName {
		return Spec{}, fmt.Errorf("invalid rule pack name %q", name)
	}
	return Spec{Kind: PackSpec, Name: name, Profile: profile}, nil
}

func (s Spec) String() string {
	name := starterName
	switch s.Kind {
	case PackSpec:
		name = s.Name
	case PathSpec:
		name = s.Path
	}
	switch {
	case s.ProfileFile != "":
		name += ":" + s.ProfileFile
	case s.Profile != "":
		name += ":" + s.Profile
	}
	return name
}

// profileFile reports a local list path, such as ./security.list, rather than a pack profile name.
func profileFile(value string) bool {
	return strings.ContainsAny(value, `/\`) || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../")
}
