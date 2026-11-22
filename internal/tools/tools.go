// Package tools locates scanner executables installed by the user or by Pug.
package tools

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ZAPImage is the image exercised by the live ZAP integration test.
const ZAPImage = "ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"

func Home() (string, error) {
	if home := os.Getenv("PUG_HOME"); home != "" {
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("PUG_HOME must be an absolute path")
		}
		return home, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "pug"), nil
}

// IsolatedEnv returns a tool's environment, or nil to inherit the process environment.
// naabu writes config under HOME (XDG_CONFIG_HOME on Linux) and reads cloud upload settings.
// zizmor gets a copy with GitHub tokens removed.
func IsolatedEnv(tool, dir string) []string {
	switch tool {
	case "naabu":
		return append(os.Environ(), "HOME="+dir, "XDG_CONFIG_HOME="+dir, "DISABLE_CLOUD_UPLOAD=true", "PDCP_API_KEY=")
	case "zizmor":
		// These tokens make zizmor call GitHub. Pug passes --offline and still removes them.
		return withoutEnv(os.Environ(), "GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN")
	}
	return nil
}

func withoutEnv(env []string, keys ...string) []string {
	drop := map[string]bool{}
	for _, key := range keys {
		drop[key] = true
	}
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if drop[key] {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// LookPath preserves PATH precedence and only falls back for bare tool names.
func LookPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err == nil || filepath.Base(name) != name {
		return path, err
	}
	home, homeErr := Home()
	if homeErr != nil {
		return "", homeErr
	}
	path, managedErr := exec.LookPath(filepath.Join(home, "bin", name))
	if managedErr == nil {
		return path, nil
	}
	return "", err
}
