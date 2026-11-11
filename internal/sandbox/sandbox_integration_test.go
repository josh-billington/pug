//go:build integration

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/josh-billington/pug/internal/runner"
)

func gitFixture(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	commands := [][]string{
		{"init", "-q"}, {"config", "user.name", "Pug test"}, {"config", "user.email", "test@example.invalid"},
	}
	for _, args := range commands {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %s, %v", output, err)
		}
	}
	return repo
}

func commitFixture(t *testing.T, repo string) {
	t.Helper()
	for _, args := range [][]string{{"add", "."}, {"-c", "commit.gpgsign=false", "commit", "-qm", "fixture"}} {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("commit fixture: %s, %v", data, err)
		}
	}
}

func TestSnapshotBoundaries(t *testing.T) {
	repo := gitFixture(t)
	for name, data := range map[string]string{"app.txt": "tracked", ".env": "not for the container"} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commitFixture(t, repo)
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("host only"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(t.TempDir(), "snapshot")
	commit, omitted, err := snapshot(t.Context(), repo, stage, runner.Local{})
	if err != nil || len(commit) != 40 || len(omitted) != 1 || omitted[0] != ".env" {
		t.Fatalf("snapshot failed: commit=%q omitted=%v error=%v", commit, omitted, err)
	}
	for _, name := range []string{".env", "untracked.txt"} {
		if _, err := os.Stat(filepath.Join(stage, name)); !os.IsNotExist(err) {
			t.Fatalf("host-only file %q entered snapshot", name)
		}
	}
	data, err := os.ReadFile(filepath.Join(stage, "app.txt"))
	if err != nil || string(data) != "tracked" {
		t.Fatalf("tracked source missing: %q, %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(repo, "app.txt"), []byte("dirty"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := snapshot(t.Context(), repo, filepath.Join(t.TempDir(), "dirty"), runner.Local{}); err == nil {
		t.Fatal("dirty checkout accepted")
	}
}

func TestSnapshotRejectsSymlink(t *testing.T) {
	repo := gitFixture(t)
	if err := os.Symlink("/etc/passwd", filepath.Join(repo, "escape")); err != nil {
		t.Skip(err)
	}
	commitFixture(t, repo)
	if _, _, err := snapshot(t.Context(), repo, filepath.Join(t.TempDir(), "snapshot"), runner.Local{}); err == nil {
		t.Fatal("tracked symlink accepted")
	}
}

func TestShellArgumentsRemainLiteral(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX launcher")
	}
	value := "spaces ' quotes $(false); `false` $HOME\nnew line"
	cmd := exec.Command("sh", "-c", shellJoin([]string{"printf", "%s", value}))
	output, err := cmd.CombinedOutput()
	if err != nil || string(output) != value {
		t.Fatalf("arguments were interpreted as shell syntax: %q, %v", output, err)
	}
}

func TestDockerIsolation(t *testing.T) {
	image := os.Getenv("PUG_TEST_SANDBOX_IMAGE")
	if image == "" {
		t.Skip("set PUG_TEST_SANDBOX_IMAGE to a locally installed digest-pinned image with /bin/sh")
	}
	repo := gitFixture(t)
	if err := os.WriteFile(filepath.Join(repo, "app.txt"), []byte("tracked"), 0o600); err != nil {
		t.Fatal(err)
	}
	commitFixture(t, repo)
	options := Options{
		Repo: repo, Image: image, Timeout: time.Minute,
		Command: []string{"sh", "-c", `
test "$(cat app.txt)" = tracked &&
test "$(id -u)" = 65534 &&
! touch /source/forbidden &&
! touch /forbidden &&
test ! -e /var/run/docker.sock &&
test ! -e /sys/class/net/eth0 &&
test -e /sys/class/net/lo &&
touch /scratch/allowed`},
	}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	r, err := Run(context.Background(), options, runner.Local{}, "integration")
	if err != nil || !r.Complete {
		t.Fatalf("Docker isolation check failed: %+v, %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(repo, "forbidden")); !os.IsNotExist(err) {
		t.Fatal("sandbox modified checkout")
	}
	if !strings.Contains(strings.Join(r.Checks[0].Command, " "), "--network=none") {
		t.Fatal("isolation evidence missing")
	}
}

func TestDockerTimeout(t *testing.T) {
	image := os.Getenv("PUG_TEST_SANDBOX_IMAGE")
	if image == "" {
		t.Skip("set PUG_TEST_SANDBOX_IMAGE for real Docker timeout verification")
	}
	repo := gitFixture(t)
	if err := os.WriteFile(filepath.Join(repo, "app.txt"), []byte("tracked"), 0o600); err != nil {
		t.Fatal(err)
	}
	commitFixture(t, repo)
	options := Options{
		Repo: repo, Image: image, Timeout: 3 * time.Second,
		Command: []string{"sleep", "60"},
	}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	r, err := Run(t.Context(), options, runner.Local{}, "integration")
	if err != nil || r.Complete || len(r.Checks) != 1 {
		t.Fatalf("timeout did not return incomplete evidence: %+v, %v", r, err)
	}
	if !strings.Contains(r.Checks[0].Reason, "timed out") || strings.Contains(r.Checks[0].Reason, "cleanup") {
		t.Fatalf("unexpected timeout or failed cleanup: %+v", r.Checks[0])
	}
}
