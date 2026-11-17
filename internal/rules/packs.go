// Package rules installs pinned OpenGrep rule packs and composes the rules
// selected for a scan into one config.
package rules

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

// Pack is a pinned upstream rule repository. ProfilesDir holds curated
// selections as "<name>.list" files of "path:rule-id" lines.
type Pack struct {
	Name           string   `json:"name"`
	Repo           string   `json:"repo"`
	Commit         string   `json:"commit"`
	SHA256         string   `json:"sha256"`
	License        string   `json:"license"`
	RuleDirs       []string `json:"rule_dirs"`
	ProfilesDir    string   `json:"profiles_dir,omitempty"`
	DefaultProfile string   `json:"default_profile,omitempty"`
}

// TarballURL is the GitHub archive of the pinned commit; its digest is SHA256.
func (p Pack) TarballURL() string {
	return "https://codeload.github.com/" + p.Repo + "/tar.gz/" + p.Commit
}

//go:embed packs.json
var packData []byte

// Packs is the embedded registry, in display order.
var Packs = mustParsePacks(packData)

var (
	packName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	hex40    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ParsePacks decodes and validates a registry. The pin bumper uses it on
// packs.json before rewriting the file.
func ParsePacks(data []byte) ([]Pack, error) {
	var packs []Pack
	if err := json.Unmarshal(data, &packs); err != nil {
		return nil, fmt.Errorf("decode rule pack registry: %w", err)
	}
	seen := map[string]bool{}
	for _, p := range packs {
		switch {
		case !packName.MatchString(p.Name) || p.Name == starterName || seen[p.Name]:
			return nil, fmt.Errorf("rule pack name %q is invalid or repeated", p.Name)
		case p.Repo == "" || p.License == "" || len(p.RuleDirs) == 0:
			return nil, fmt.Errorf("rule pack %s needs a repo, license, and rule dirs", p.Name)
		case (p.DefaultProfile == "") != (p.ProfilesDir == ""):
			return nil, fmt.Errorf("rule pack %s needs both or neither of profiles_dir and default_profile", p.Name)
		}
		seen[p.Name] = true
	}
	return packs, nil
}

func mustParsePacks(data []byte) []Pack {
	packs, err := ParsePacks(data)
	if err != nil {
		panic(err)
	}
	return packs
}

// Pinned reports whether the pack names an exact commit and tarball digest.
func (p Pack) Pinned() bool {
	return hex40.MatchString(p.Commit) && hex64.MatchString(p.SHA256)
}

// Lookup returns the registry entry for name.
func Lookup(name string) (Pack, bool) {
	i := slices.IndexFunc(Packs, func(p Pack) bool { return p.Name == name })
	if i < 0 {
		return Pack{}, false
	}
	return Packs[i], true
}

// Names lists the registry's pack names.
func Names() []string {
	names := make([]string, len(Packs))
	for i, p := range Packs {
		names[i] = p.Name
	}
	return names
}
