// Package tools locates scanner executables installed by the user or by Pug.
package tools

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
