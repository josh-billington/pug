// Package sandbox runs an explicitly selected command against an isolated source snapshot.
package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/runner"
	"github.com/josh-billington/pug/internal/scanner"
)

type Options struct {
	Repo    string
	Image   string
	Command []string
	AppJSON string
	Timeout time.Duration
	app     []string
}

func Validate(options *Options) error {
	if !scanner.ValidImage(options.Image) {
		return fmt.Errorf("sandbox requires a locally installed image pinned by sha256 digest")
	}
	if options.Timeout <= 0 || options.Timeout > 30*time.Minute {
		return fmt.Errorf("sandbox timeout must be positive and at most 30m")
	}
	if len(options.Command) == 0 || options.Command[0] == "" {
		return fmt.Errorf("sandbox requires a command after --")
	}
	path, err := filepath.Abs(options.Repo)
	if err != nil {
		return fmt.Errorf("resolve repository: %w", err)
	}
	options.Repo = path
	if options.AppJSON != "" {
		if err := json.Unmarshal([]byte(options.AppJSON), &options.app); err != nil {
			return fmt.Errorf("app-command must be a JSON array of arguments: %w", err)
		}
		if len(options.app) == 0 || options.app[0] == "" {
			return fmt.Errorf("app-command must include an executable")
		}
	}
	for _, arg := range append(append([]string{}, options.Command...), options.app...) {
		if strings.ContainsRune(arg, 0) {
			return fmt.Errorf("command arguments must not contain NUL bytes")
		}
	}
	return nil
}

func Run(ctx context.Context, options Options, executor runner.Executor, version string) (report.Report, error) {
	r := report.Report{
		SchemaVersion: "1", Version: version, Target: options.Repo, StartedAt: time.Now().UTC(),
		Checks: []report.Check{}, NotTested: []report.CoverageGap{},
		Limitations: []string{
			"A successful sandbox command is not a security assessment or proof of remediation.",
			"No model, credentials, or pentesting agent is bundled. The image must contain the command and dependencies.",
			"The container has no external network. An app and offline agent may communicate over container loopback.",
			"Only clean tracked regular files are copied; common credential filenames are omitted, but source may embed secrets.",
			"Container stdout is hashed and discarded, not printed or promoted to trusted findings.",
			"Docker isolation shares a kernel and is not a guarantee against container escape.",
			"The optional app starts concurrently; the agent command must wait for application readiness.",
		},
	}
	temp, err := os.MkdirTemp("", "pug-sandbox-*")
	if err != nil {
		return r, fmt.Errorf("create sandbox staging directory: %w", err)
	}
	defer os.RemoveAll(temp)
	runCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	stage := filepath.Join(temp, "source")
	commit, omitted, err := snapshot(runCtx, options.Repo, stage, executor)
	if err != nil {
		return r, err
	}
	r.Limitations = append(r.Limitations, "Snapshot commit: "+commit)
	for _, name := range omitted {
		r.NotTested = append(r.NotTested, report.CoverageGap{Check: "snapshot", Reason: "credential filename omitted: " + name})
	}
	launcher := filepath.Join(temp, "launch.sh")
	if err := os.WriteFile(launcher, []byte(launchScript(options)), 0o644); err != nil {
		return r, fmt.Errorf("write sandbox launcher: %w", err)
	}
	// The container user (65534) must read the launcher regardless of the host umask.
	if err := os.Chmod(launcher, 0o644); err != nil {
		return r, fmt.Errorf("set sandbox launcher permissions: %w", err)
	}
	name := filepath.Base(temp)
	invocation := runner.Invocation{Program: "docker", Args: []string{
		"run", "--rm", "--pull=never", "--name", name,
		"--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user=65534:65534", "--cpus=1", "--memory=512m", "--memory-swap=512m", "--pids-limit=128",
		"--tmpfs=/scratch:rw,nosuid,nodev,size=128m,mode=1777", "--env=HOME=/scratch", "--env=TMPDIR=/scratch",
		"--mount", "type=bind,src=" + stage + ",dst=/source,readonly",
		"--mount", "type=bind,src=" + launcher + ",dst=/pug-launch.sh,readonly",
		"--workdir=/scratch", "--entrypoint=/bin/sh", options.Image, "/pug-launch.sh",
	}}
	check := report.Check{
		Name: "sandbox", Tool: "docker", Version: options.Image,
		StartedAt: time.Now().UTC(), Command: append([]string{"docker"}, invocation.Args...),
		Findings: []report.Finding{}, Status: "failed", ExitCode: -1,
	}
	started := time.Now()
	result := executor.Run(runCtx, invocation)
	check.DurationMS = time.Since(started).Milliseconds()
	check.ExitCode = result.ExitCode
	check.EvidenceSHA256 = report.Digest(result.Stdout)
	check.Reason = "container or command failed; inspect the pinned image and command"
	if result.Err == nil && result.ExitCode == 0 && !result.Truncated {
		check.Status, check.Reason = "completed", ""
	}
	if runCtx.Err() != nil {
		check.Status, check.Reason = "failed", "sandbox cancelled or timed out"
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cleanupCancel()
	if err := runner.RemoveContainer(cleanupCtx, executor, name); err != nil {
		check.Status = "failed"
		if check.Reason != "" {
			check.Reason += "; "
		}
		check.Reason += err.Error()
	}
	r.Checks = append(r.Checks, check)
	omissions := append([]report.CoverageGap{}, r.NotTested...)
	r.Finalize(map[string]bool{"sandbox": true}, scanner.AllChecks)
	r.NotTested = append(r.NotTested, omissions...)
	return r, nil
}

func launchScript(options Options) string {
	var script strings.Builder
	script.WriteString("#!/bin/sh\nset -eu\nmkdir -p /scratch/work\ncp -R /source/. /scratch/work/\ncd /scratch/work\n")
	if len(options.app) > 0 {
		script.WriteString(shellJoin(options.app) + " >/scratch/app.log 2>&1 &\napp_pid=$!\n")
		script.WriteString("trap 'kill \"$app_pid\" 2>/dev/null || true' EXIT INT TERM\n")
		script.WriteString(shellJoin(options.Command) + "\n")
		return script.String()
	}
	script.WriteString("exec " + shellJoin(options.Command) + "\n")
	return script.String()
}

func shellJoin(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(arg, "'", "'\"'\"'")+"'")
	}
	return strings.Join(quoted, " ")
}

func git(ctx context.Context, repo string, args []string, executor runner.Executor) ([]byte, error) {
	base := []string{"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", repo}
	result := executor.Run(ctx, runner.Invocation{Program: "git", Args: append(base, args...)})
	if result.Err != nil || result.ExitCode != 0 || result.Truncated {
		return nil, fmt.Errorf("cannot inspect clean Git checkout (git %s)", strings.Join(args, " "))
	}
	return result.Stdout, nil
}

func snapshot(ctx context.Context, repo, stage string, executor runner.Executor) (string, []string, error) {
	top, err := git(ctx, repo, []string{"rev-parse", "--show-toplevel"}, executor)
	if err != nil {
		return "", nil, err
	}
	resolved, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return "", nil, err
	}
	if strings.TrimSpace(string(top)) != resolved {
		return "", nil, fmt.Errorf("sandbox --repo must be the Git checkout root")
	}
	status, err := git(ctx, repo, []string{"status", "--porcelain", "--untracked-files=no"}, executor)
	if err != nil {
		return "", nil, err
	}
	if len(status) > 0 {
		return "", nil, fmt.Errorf("sandbox requires a clean tracked working tree; commit or stash changes first")
	}
	commit, err := git(ctx, repo, []string{"rev-parse", "HEAD"}, executor)
	if err != nil {
		return "", nil, err
	}
	files, err := git(ctx, repo, []string{"ls-files", "--stage", "-z"}, executor)
	if err != nil {
		return "", nil, err
	}
	if err := os.Mkdir(stage, 0o755); err != nil {
		return "", nil, err
	}
	root, err := os.OpenRoot(repo)
	if err != nil {
		return "", nil, fmt.Errorf("open snapshot root: %w", err)
	}
	defer root.Close()
	omitted := []string{}
	var total int64
	count := 0
	for _, entry := range strings.Split(string(files), "\x00") {
		if entry == "" {
			continue
		}
		meta, path, ok := strings.Cut(entry, "\t")
		if !ok || !filepath.IsLocal(path) {
			return "", nil, fmt.Errorf("invalid tracked snapshot path")
		}
		mode := strings.Fields(meta)[0]
		if mode != "100644" && mode != "100755" {
			return "", nil, fmt.Errorf("snapshot rejects symlinks and submodules: %q", path)
		}
		if credentialPath(path) {
			omitted = append(omitted, path)
			continue
		}
		count++
		if count > 5000 || ctx.Err() != nil {
			return "", nil, fmt.Errorf("snapshot cancelled or exceeds 5000 files")
		}
		info, err := root.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", nil, fmt.Errorf("snapshot file is not regular: %q", path)
		}
		data, err := readSnapshotFile(root, path)
		if err != nil {
			return "", nil, err
		}
		total += int64(len(data))
		if total > 50<<20 {
			return "", nil, fmt.Errorf("snapshot exceeds 50 MiB")
		}
		destination := filepath.Join(stage, path)
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return "", nil, err
		}
		permissions := os.FileMode(0o644)
		if mode == "100755" {
			permissions = 0o755
		}
		if err := os.WriteFile(destination, data, permissions); err != nil {
			return "", nil, err
		}
	}
	if count == 0 {
		return "", nil, fmt.Errorf("snapshot has no eligible tracked files")
	}
	if err := shareTree(stage); err != nil {
		return "", nil, fmt.Errorf("set snapshot permissions: %w", err)
	}
	after, err := git(ctx, repo, []string{"status", "--porcelain", "--untracked-files=no"}, executor)
	if err != nil || len(after) > 0 {
		return "", nil, fmt.Errorf("tracked checkout changed during snapshot")
	}
	head, err := git(ctx, repo, []string{"rev-parse", "HEAD"}, executor)
	if err != nil || string(head) != string(commit) {
		return "", nil, fmt.Errorf("checkout commit changed during snapshot")
	}
	return strings.TrimSpace(string(commit)), omitted, nil
}

// shareTree makes the staged snapshot readable and traversable by the unprivileged
// container user, independent of the host umask, while preserving executable bits.
func shareTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		return os.Chmod(path, mode)
	})
}

func readSnapshotFile(root *os.Root, path string) ([]byte, error) {
	file, err := root.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open snapshot file %q: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (50<<20)+1))
	if err != nil || len(data) > 50<<20 {
		return nil, fmt.Errorf("snapshot file exceeds limit or cannot be read: %q", path)
	}
	return data, nil
}

func credentialPath(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(strings.ToLower(path)), "/") {
		if part == ".git" || part == ".ssh" || part == ".aws" || part == ".gnupg" {
			return true
		}
	}
	name := strings.ToLower(filepath.Base(path))
	if name == ".env" || strings.HasPrefix(name, ".env.") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") {
		return true
	}
	switch name {
	case "id_rsa", "id_ed25519", ".npmrc", ".netrc", ".pypirc", "credentials", "credentials.json":
		return true
	}
	return false
}
