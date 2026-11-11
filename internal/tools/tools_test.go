package tools

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestManagedLookupPreservesPATHAndExplicitPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executable permissions")
	}
	home := t.TempDir()
	managed := filepath.Join(home, "bin")
	if err := os.Mkdir(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	managedTool := filepath.Join(managed, "gitleaks")
	if err := os.WriteFile(managedTool, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PUG_HOME", home)
	t.Setenv("PATH", "")
	if got, err := LookPath("gitleaks"); err != nil || got != managedTool {
		t.Fatalf("managed executable not found: %s, %v", got, err)
	}
	pathDir := t.TempDir()
	pathTool := filepath.Join(pathDir, "gitleaks")
	if err := os.WriteFile(pathTool, []byte("user executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)
	if got, err := LookPath("gitleaks"); err != nil || got != pathTool {
		t.Fatalf("PATH did not take precedence: %s, %v", got, err)
	}
	if _, err := LookPath(filepath.Join(t.TempDir(), "gitleaks")); err == nil {
		t.Fatal("explicit missing path fell back to a managed tool")
	}
	if _, err := LookPath("missing"); !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("missing executable did not preserve ErrNotFound: %v", err)
	}
	t.Setenv("PUG_HOME", "relative")
	if _, err := Home(); err == nil {
		t.Fatal("relative PUG_HOME accepted")
	}
}
