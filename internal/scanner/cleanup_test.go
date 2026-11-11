package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josh-billington/pug/internal/runner"
)

// lockedWorkspace builds temp/zap/locked/report.json with the locked directory
// read-only, which a non-root host user cannot empty with os.RemoveAll. This
// stands in for a container-owned directory the host has no rights over.
func lockedWorkspace(t *testing.T) (temp, work string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root can remove read-only directories")
	}
	temp = t.TempDir()
	work = filepath.Join(temp, "zap")
	locked := filepath.Join(work, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "report.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if err := os.RemoveAll(temp); err == nil {
		t.Fatal("precondition: host removal should fail on a read-only directory")
	}
	return temp, work
}

// purgeExecutor simulates the cleanup container by emptying the mounted directory.
func purgeExecutor(t *testing.T, calls *[]runner.Invocation, exit int) runner.Executor {
	return executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		*calls = append(*calls, i)
		if i.Program != "docker" || len(i.Args) == 0 || i.Args[0] != "run" {
			return runner.Result{} // docker rm / ps: container already gone
		}
		if exit != 0 {
			return runner.Result{ExitCode: exit}
		}
		src := ""
		for _, arg := range i.Args {
			if v, ok := strings.CutPrefix(arg, "type=bind,src="); ok {
				src = strings.TrimSuffix(v, ",dst=/pug-clean")
			}
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			path := filepath.Join(src, entry.Name())
			_ = filepath.Walk(path, func(p string, info os.FileInfo, _ error) error {
				if info != nil && info.IsDir() {
					_ = os.Chmod(p, 0o755)
				}
				return nil
			})
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
		}
		return runner.Result{}
	})
}

func TestCleanupWorkspaceFallsBackToContainer(t *testing.T) {
	temp, work := lockedWorkspace(t)
	var calls []runner.Invocation
	p := plan{mount: work, image: "zap@sha256:abc"}
	if err := cleanupWorkspace(t.Context(), purgeExecutor(t, &calls, 0), temp, p); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if _, err := os.Lstat(temp); !os.IsNotExist(err) {
		t.Fatalf("workspace still present: %v", err)
	}
	if len(calls) == 0 || calls[0].Args[0] != "run" {
		t.Fatalf("expected cleanup container run, got %+v", calls)
	}
	args := calls[0].Args
	for _, want := range []string{"--rm", "--pull=never", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "zap@sha256:abc", "type=bind,src=" + work + ",dst=/pug-clean"} {
		if !slices.Contains(args, want) {
			t.Errorf("cleanup container missing %q: %v", want, args)
		}
	}
	if slices.Contains(args, "type=bind,src="+temp+",dst=/pug-clean") {
		t.Error("private parent directory must not be mounted")
	}
	if slices.Contains(args, "--user") {
		t.Error("cleanup must run as the image's default user, the same user that wrote the files")
	}
}

func TestCleanupWorkspaceReportsFallbackFailure(t *testing.T) {
	temp, work := lockedWorkspace(t)
	var calls []runner.Invocation
	err := cleanupWorkspace(t.Context(), purgeExecutor(t, &calls, 1), temp, plan{mount: work, image: "zap@sha256:abc"})
	if err == nil || !strings.Contains(err.Error(), "container cleanup fallback failed") {
		t.Fatalf("expected fallback failure, got %v", err)
	}
}

func TestCleanupWorkspaceSkipsFallbackWithoutMount(t *testing.T) {
	temp, _ := lockedWorkspace(t)
	var calls []runner.Invocation
	if err := cleanupWorkspace(t.Context(), purgeExecutor(t, &calls, 0), temp, plan{}); err == nil {
		t.Fatal("expected host removal error without a container mount")
	}
	if len(calls) != 0 {
		t.Fatalf("no container should run for non-container checks: %+v", calls)
	}
}

func TestCleanupWorkspaceIgnoresCancelledScanContext(t *testing.T) {
	temp, work := lockedWorkspace(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var calls []runner.Invocation
	exec := executorFunc(func(c context.Context, i runner.Invocation) runner.Result {
		if c.Err() != nil {
			return runner.Result{ExitCode: -1, Err: c.Err()}
		}
		return purgeExecutor(t, &calls, 0).Run(c, i)
	})
	if err := cleanupWorkspace(ctx, exec, temp, plan{mount: work, image: "zap@sha256:abc"}); err != nil {
		t.Fatalf("cleanup should survive a cancelled scan: %v", err)
	}
}
