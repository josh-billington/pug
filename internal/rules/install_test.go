package rules

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/josh-billington/pug/internal/runner"
)

type executorFunc func(context.Context, runner.Invocation) runner.Result

func (f executorFunc) Run(ctx context.Context, i runner.Invocation) runner.Result { return f(ctx, i) }

func TestInstallReplacesOnlyAfterGitSucceeds(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name string
		fail bool
	}{
		{name: "replace"}, {name: "failed clone", fail: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			destination := Dir(home, "fixture")
			if err := os.MkdirAll(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(destination, "old.yml")
			if err := os.WriteFile(old, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			commit := strings.Repeat("a", 40)
			executor := executorFunc(func(ctx context.Context, i runner.Invocation) runner.Result {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("git has no deadline")
				}
				if !slices.Contains(i.Env, "GIT_TERMINAL_PROMPT=0") {
					t.Fatal("git can prompt")
				}
				switch {
				case slices.Contains(i.Args, "clone"):
					if testCase.fail {
						return runner.Result{ExitCode: 1, Err: errors.New("offline")}
					}
					tree := i.Args[len(i.Args)-1]
					if err := os.MkdirAll(tree, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(tree, "new.yml"), []byte("new"), 0o600); err != nil {
						t.Fatal(err)
					}
				case slices.Contains(i.Args, "rev-parse"):
					return runner.Result{Stdout: []byte(commit + "\n")}
				default:
					t.Fatalf("unexpected git command: %v", i.Args)
				}
				return runner.Result{}
			})
			got, err := Install(t.Context(), executor, home, InstallSpec{Name: "fixture", URL: "https://example.com/rules"})
			if testCase.fail {
				if err == nil {
					t.Fatal("failed clone succeeded")
				}
				if data, err := os.ReadFile(old); err != nil || string(data) != "old" {
					t.Fatalf("previous pack lost: %q, %v", data, err)
				}
			} else {
				if err != nil || got != commit {
					t.Fatalf("install = %q, %v", got, err)
				}
				if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("old file survived: %v", err)
				}
				if data, err := os.ReadFile(filepath.Join(destination, "new.yml")); err != nil || string(data) != "new" {
					t.Fatalf("new file missing: %q, %v", data, err)
				}
			}
			entries, err := os.ReadDir(filepath.Join(home, "rules"))
			if err != nil || len(entries) != 1 {
				t.Fatalf("install left workspaces: %v, %v", entries, err)
			}
		})
	}
}

func TestInstallRejectsMismatchedCommit(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		if i.Args[2] == "clone" {
			if err := os.MkdirAll(i.Args[len(i.Args)-1], 0o700); err != nil {
				t.Fatal(err)
			}
		}
		return runner.Result{Stdout: []byte(strings.Repeat("b", 40))}
	})
	if _, err := Install(t.Context(), executor, home, InstallSpec{Name: "fixture", URL: "https://example.com/rules", Commit: strings.Repeat("a", 40)}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("commit mismatch accepted: %v", err)
	}
	if _, err := os.Stat(Dir(home, "fixture")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched checkout installed: %v", err)
	}
}

func TestInstallRemovesOnlyStaleWorkspaces(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	parent := filepath.Join(home, "rules")
	stale := filepath.Join(parent, ".tmp-fixture-crashed")
	fresh := filepath.Join(parent, ".tmp-fixture-running")
	other := filepath.Join(parent, "unrelated")
	for _, dir := range []string{stale, fresh, other} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleAfter)
	for _, dir := range []string{stale, other} {
		if err := os.Chtimes(dir, old, old); err != nil {
			t.Fatal(err)
		}
	}
	missingGit := executorFunc(func(context.Context, runner.Invocation) runner.Result {
		return runner.Result{ExitCode: -1, Err: exec.ErrNotFound}
	})
	if _, err := Install(t.Context(), missingGit, home, InstallSpec{Name: "fixture", URL: "https://example.com/rules"}); err == nil || !strings.Contains(err.Error(), "pug doctor") {
		t.Fatalf("missing git error: %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale workspace survived: %v", err)
	}
	for _, dir := range []string{fresh, other} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("removed %s: %v", dir, err)
		}
	}
}

func TestInstallGitCannotAskForCredentials(t *testing.T) {
	t.Setenv("SSH_ASKPASS", "/bin/false")
	t.Setenv("GIT_ASKPASS", "/bin/false")
	var invocations []runner.Invocation
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		invocations = append(invocations, i)
		return runner.Result{ExitCode: 128, Err: errors.New("authentication required")}
	})
	if _, err := Install(t.Context(), executor, t.TempDir(), InstallSpec{Name: "fixture", URL: "https://example.com/rules"}); err == nil {
		t.Fatal("failed clone succeeded")
	}
	if len(invocations) == 0 {
		t.Fatal("git was not run")
	}
	for _, i := range invocations {
		for _, value := range i.Env {
			if strings.HasPrefix(value, "SSH_ASKPASS=") || strings.HasPrefix(value, "GIT_ASKPASS=") {
				t.Fatalf("git inherited %s", value)
			}
		}
		if !slices.Contains(i.Args, "core.askPass=") {
			t.Fatalf("git can use a configured askpass helper: %v", i.Args)
		}
	}
}
