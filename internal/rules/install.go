package rules

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/josh-billington/pug/internal/runner"
)

const staleAfter = time.Hour

func Dir(home, name string) string { return filepath.Join(home, "rules", name) }

func Install(ctx context.Context, executor runner.Executor, home string, spec InstallSpec) (string, error) {
	parent := filepath.Join(home, "rules")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create rules directory: %w", err)
	}
	if err := removeStale(parent, spec.Name); err != nil {
		return "", err
	}
	work, err := os.MkdirTemp(parent, ".tmp-"+spec.Name+"-")
	if err != nil {
		return "", fmt.Errorf("create install workspace: %w", err)
	}
	defer os.RemoveAll(work)
	tree := filepath.Join(work, "tree")
	if _, err := runGit(ctx, executor, "", []string{"clone", "--depth", "1", "--no-tags", "--template=", "--", spec.URL, tree}); err != nil {
		return "", err
	}
	if spec.Commit != "" {
		if _, err := runGit(ctx, executor, tree, []string{"fetch", "--depth", "1", "--no-tags", "--", "origin", spec.Commit}); err != nil {
			if len(spec.Commit) >= 40 {
				return "", err
			}
			// Servers generally require a full object ID when fetching an unadvertised commit.
			if _, err := runGit(ctx, executor, tree, []string{"fetch", "--unshallow", "--no-tags", "--", "origin"}); err != nil {
				return "", err
			}
			resolved, err := runGit(ctx, executor, tree, []string{"rev-parse", "--verify", spec.Commit + "^{commit}"})
			if err != nil {
				return "", err
			}
			if _, err := runGit(ctx, executor, tree, []string{"checkout", "--detach", resolved, "--"}); err != nil {
				return "", err
			}
		} else {
			if _, err := runGit(ctx, executor, tree, []string{"checkout", "--detach", "FETCH_HEAD", "--"}); err != nil {
				return "", err
			}
		}
	}
	commit, err := runGit(ctx, executor, tree, []string{"rev-parse", "--verify", "HEAD"})
	if err != nil {
		return "", err
	}
	if spec.Commit != "" && !strings.HasPrefix(commit, spec.Commit) {
		return "", fmt.Errorf("installed commit %s does not match requested commit %s", commit, spec.Commit)
	}
	destination := Dir(home, spec.Name)
	previous := filepath.Join(work, "previous")
	if err := os.Rename(destination, previous); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("move previous install: %w", err)
	}
	if err := os.Rename(tree, destination); err != nil {
		restoreErr := os.Rename(previous, destination)
		if errors.Is(restoreErr, fs.ErrNotExist) {
			restoreErr = nil
		}
		return "", fmt.Errorf("replace rule pack: %w", errors.Join(err, restoreErr))
	}
	return commit, nil
}

func Commit(ctx context.Context, executor runner.Executor, dir string) (string, error) {
	if _, err := os.Lstat(filepath.Join(dir, ".git")); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("inspect rule checkout: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return runGit(ctx, executor, dir, []string{"rev-parse", "--verify", "HEAD"})
}

func runGit(ctx context.Context, executor runner.Executor, dir string, args []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	env := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GIT_") {
			env = append(env, value)
		}
	}
	env = append(env, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_ATTR_NOSYSTEM=1")
	args = append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
	result := executor.Run(ctx, runner.Invocation{Program: "git", Args: args, Dir: dir, Env: env})
	if errors.Is(result.Err, exec.ErrNotFound) {
		return "", fmt.Errorf("git is required to install and inspect rule packs; run pug doctor")
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("git cancelled or timed out: %w", ctx.Err())
	}
	if result.Err != nil || result.ExitCode != 0 || result.Truncated {
		return "", fmt.Errorf("git %s failed (exit %d): %s", args[2], result.ExitCode, strings.TrimSpace(string(result.Stderr)))
	}
	return strings.TrimSpace(string(result.Stdout)), nil
}

func removeStale(parent, name string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return fmt.Errorf("read install workspaces: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".tmp-"+name+"-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || time.Since(info.ModTime()) < staleAfter {
			continue
		}
		if err := os.RemoveAll(filepath.Join(parent, entry.Name())); err != nil {
			return fmt.Errorf("remove stale install directory: %w", err)
		}
	}
	return nil
}

func Profiles(dir string) ([]string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open rule pack: %w", err)
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), "configs")
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read rule profiles: %w", err)
	}
	profiles := []string{}
	for _, entry := range entries {
		if name, ok := strings.CutSuffix(entry.Name(), ".list"); ok && entry.Type().IsRegular() && profileName.MatchString(name) {
			profiles = append(profiles, name)
		}
	}
	return profiles, nil
}
