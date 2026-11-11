package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*Options)
	}{
		{name: "mutable image", edit: func(o *Options) { o.Image = "alpine:latest" }},
		{name: "excessive runtime", edit: func(o *Options) { o.Timeout = time.Hour }},
		{name: "no command", edit: func(o *Options) { o.Command = nil }},
		{name: "empty app", edit: func(o *Options) { o.AppJSON = `[]` }},
		{name: "app shell string", edit: func(o *Options) { o.AppJSON = `"python app.py"` }},
		{name: "NUL argument", edit: func(o *Options) { o.Command = []string{"echo", "a\x00b"} }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			options := Options{Image: "alpine@sha256:" + strings.Repeat("a", 64), Repo: ".", Command: []string{"true"}, Timeout: time.Minute}
			tt.edit(&options)
			if err := Validate(&options); err == nil {
				t.Fatal("unsafe sandbox options accepted")
			}
		})
	}
}

func TestCredentialExclusions(t *testing.T) {
	t.Parallel()
	for _, name := range []string{".env", "nested/.env.production", ".aws/config", "keys/server.PEM", "id_ed25519", "nested/.npmrc"} {
		t.Run(name, func(t *testing.T) {
			if !credentialPath(name) {
				t.Fatalf("credential path %q would enter snapshot", name)
			}
		})
	}
	if credentialPath("src/main.go") || credentialPath("docs/environment.md") {
		t.Fatal("ordinary source incorrectly excluded")
	}
}

func TestShareTreeIgnoresRestrictiveUmask(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "source")
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	plain, script := filepath.Join(nested, "main.go"), filepath.Join(root, "run.sh")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "a"), nested} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := shareTree(root); err != nil {
		t.Fatal(err)
	}
	want := map[string]os.FileMode{root: 0o755, filepath.Join(root, "a"): 0o755, nested: 0o755, plain: 0o644, script: 0o755}
	for path, mode := range want {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode = %o, want %o", path, info.Mode().Perm(), mode)
		}
	}
}
