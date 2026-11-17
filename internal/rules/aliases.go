// Package rules installs OpenGrep rule repositories and composes selected rules.
package rules

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

var Aliases = map[string]string{
	"opengrep": "https://github.com/opengrep/opengrep-rules.git",
	"amplify":  "https://github.com/amplify-security/opengrep-rules.git",
	"aikido":   "https://github.com/AikidoSec/opengrep-rules.git",
}

var (
	packName = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
	commitID = regexp.MustCompile(`^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
)

type InstallSpec struct {
	Name   string
	URL    string
	Commit string
}

func Names() []string {
	names := make([]string, 0, len(Aliases))
	for name := range Aliases {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func ParseInstallSpec(value string) (InstallSpec, error) {
	if value == "" || strings.HasPrefix(value, "-") {
		return InstallSpec{}, fmt.Errorf("invalid rule repository %q", value)
	}
	repo, commit := value, ""
	if i := strings.LastIndexByte(value, '@'); i >= 0 {
		repo, commit = value[:i], value[i+1:]
		if !commitID.MatchString(commit) {
			return InstallSpec{}, fmt.Errorf("invalid commit %q; use the full 40- or 64-character commit ID", commit)
		}
		commit = strings.ToLower(commit)
	}
	if cloneURL, ok := Aliases[repo]; ok {
		return InstallSpec{Name: repo, URL: cloneURL, Commit: commit}, nil
	}
	if strings.HasPrefix(repo, "github.com/") {
		repo = "https://" + repo
	}
	u, err := url.Parse(repo)
	if err != nil {
		return InstallSpec{}, fmt.Errorf("parse rule repository: %w", err)
	}
	validHTTPS := u.Scheme == "https" && u.Hostname() != "" && !strings.HasPrefix(u.Hostname(), "-")
	validFile := u.Scheme == "file" && u.Host == "" && strings.HasPrefix(u.Path, "/")
	if !validHTTPS && !validFile {
		return InstallSpec{}, fmt.Errorf("rule repository must be an alias or an absolute https or file URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return InstallSpec{}, fmt.Errorf("rule repository must not contain credentials, a query, or a fragment")
	}
	name := strings.TrimSuffix(path.Base(strings.TrimRight(u.Path, "/")), ".git")
	if !packName.MatchString(name) || name == starterName {
		return InstallSpec{}, fmt.Errorf("invalid rule pack name %q", name)
	}
	if _, reserved := Aliases[name]; reserved {
		return InstallSpec{}, fmt.Errorf("rule pack name %q is a built-in alias; use the alias instead", name)
	}
	return InstallSpec{Name: name, URL: u.String(), Commit: commit}, nil
}
