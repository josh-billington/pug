//go:build integration

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/tools"
)

func TestLiveFindingExitCodes(t *testing.T) {
	if _, err := tools.LookPath("gitleaks"); err != nil {
		t.Skip("install gitleaks to verify live CLI finding exits")
	}
	repo := t.TempDir()
	fakeToken := "ghp_" + "8Qj4z6P9m1R7x3L5k2N0v4B8c6D9f1G7h3J5"
	if err := os.WriteFile(filepath.Join(repo, "config.py"), []byte("token = '"+fakeToken+"'"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		failOn string
		code   int
	}{
		{name: "high findings fail", failOn: "high", code: 1},
		{name: "explicit no finding failure", failOn: "none", code: 0},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			output := filepath.Join(t.TempDir(), "report.json")
			code := Execute(t.Context(), []string{"scan", repo, "--checks", "secrets", "--fail-on", tt.failOn, "--output", output}, &stdout, &stderr, "integration")
			var r report.Report
			if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			if code != tt.code || !r.Complete || len(r.Findings()) == 0 || strings.Contains(stdout.String(), fakeToken) {
				t.Fatalf("wrong finding behavior: exit=%d complete=%t findings=%d", code, r.Complete, len(r.Findings()))
			}
			saved, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(saved, stdout.Bytes()) {
				t.Fatalf("saved report differs from stdout: %v", err)
			}
		})
	}
}

// ruleRepo commits files to a new Git repository in dir and returns the commit.
func ruleRepo(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=Pug test", "-c", "user.email=pug@example.invalid", "-c", "core.hooksPath=/dev/null"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "--template=")
	git("add", "--", ".")
	git("commit", "-q", "--no-gpg-sign", "-m", "Add rules")
	return git("rev-parse", "HEAD")
}

const teamRule = "rules:\n  - id: eval\n    languages: [python]\n    severity: ERROR\n    message: eval\n    pattern: eval(...)\n"

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("install git to run rule pack integration tests")
	}
}

func TestRulesListReportsGitCheckoutCommit(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	commit := ruleRepo(t, filepath.Join(home, "rules", "team"), map[string]string{"python/eval.yaml": teamRule})
	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"rules", "list"}, &stdout, &stderr, "integration"); code != 0 {
		t.Fatalf("rules list: %d %s", code, stderr.String())
	}
	var packs []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &packs); err != nil {
		t.Fatal(err)
	}
	for _, pack := range packs {
		if pack["name"] == "team" {
			if pack["commit"] != commit || pack["installed"] != true {
				t.Fatalf("team pack = %v, want commit %s", pack, commit)
			}
			return
		}
	}
	t.Fatalf("team pack not listed: %s", stdout.String())
}

func TestRulesInstallReportsPackCommitAndPath(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	upstream := filepath.Join(t.TempDir(), "team-rules")
	commit := ruleRepo(t, upstream, map[string]string{"python/eval.yaml": teamRule})
	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"rules", "install", "file://" + upstream}, &stdout, &stderr, "integration"); code != 0 {
		t.Fatalf("rules install: %d %s", code, stderr.String())
	}
	dir := filepath.Join(home, "rules", "team-rules")
	output := stdout.String()
	if !strings.Contains(output, dir) {
		t.Fatalf("install output %q does not name the path %s", output, dir)
	}
	if rest := strings.ReplaceAll(output, dir, ""); !strings.Contains(rest, "team-rules") || !strings.Contains(rest, commit[:7]) {
		t.Fatalf("install output %q does not name the pack and commit %s", output, commit[:7])
	}
	if data, err := os.ReadFile(filepath.Join(dir, "python", "eval.yaml")); err != nil || string(data) != teamRule {
		t.Fatalf("installed pack lacks its rules: %v", err)
	}
}

func TestRulesInstallContinuesAfterAFailedPack(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	missing := "file://" + filepath.Join(t.TempDir(), "missing-rules")
	upstream := filepath.Join(t.TempDir(), "team-rules")
	ruleRepo(t, upstream, map[string]string{"python/eval.yaml": teamRule})
	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"rules", "install", missing, "file://" + upstream}, &stdout, &stderr, "integration"); code == 0 {
		t.Fatalf("install with a failed pack exited 0: %s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(home, "rules", "team-rules", "python", "eval.yaml")); err != nil {
		t.Fatalf("pack after the failure was not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "rules", "missing-rules")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed pack left an install: %v", err)
	}
}
