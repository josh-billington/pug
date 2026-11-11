// Package setup installs missing scanners without requiring a system package manager.
package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/josh-billington/pug/internal/runner"
	"github.com/josh-billington/pug/internal/scanner"
	"github.com/josh-billington/pug/internal/tools"
)

var NativeTools = []string{"gitleaks", "actionlint", "opengrep", "trivy", "nuclei", "schemathesis"}

type Options struct {
	CheckOnly bool
	WithZAP   bool
	ZAPImage  string
	Timeout   time.Duration
	Tools     []string
}

type Tool struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type Result struct {
	Ready    bool   `json:"ready"`
	Home     string `json:"home"`
	Tools    []Tool `json:"tools"`
	Docker   Tool   `json:"docker"`
	Git      Tool   `json:"git"`
	ZAP      *Tool  `json:"zap,omitempty"`
	NextStep string `json:"next_step"`
}

func Validate(options Options) error {
	if options.Timeout <= 0 || options.Timeout > time.Hour {
		return fmt.Errorf("setup timeout must be greater than zero and at most 1h")
	}
	if len(options.Tools) == 0 {
		return fmt.Errorf("select at least one tool")
	}
	seen := map[string]bool{}
	for _, name := range options.Tools {
		valid := false
		for _, supported := range NativeTools {
			valid = valid || name == supported
		}
		if !valid || seen[name] {
			return fmt.Errorf("unknown or repeated tool %q", name)
		}
		seen[name] = true
	}
	if options.WithZAP && !scanner.ValidImage(options.ZAPImage) {
		return fmt.Errorf("ZAP image must be pinned by sha256 digest")
	}
	return nil
}

type engine struct {
	home     string
	platform string
	lookup   func(string) (string, error)
	run      func(context.Context, runner.Invocation) runner.Result
	install  func(context.Context, string) (string, error)
}

func Run(ctx context.Context, options Options, progress io.Writer) (Result, error) {
	if err := Validate(options); err != nil {
		return Result{}, err
	}
	home, err := tools.Home()
	if err != nil {
		return Result{}, err
	}
	e := engine{home: home, platform: currentPlatform(), lookup: tools.LookPath, run: (runner.Local{}).Run}
	e.install = e.installTool
	return e.setup(ctx, options, progress), nil
}

func (e engine) setup(ctx context.Context, options Options, progress io.Writer) Result {
	result := Result{Ready: true, Home: e.home, Tools: []Tool{}, NextStep: nextStep(options.Tools)}
	for _, name := range options.Tools {
		if ctx.Err() != nil {
			result.Ready = false
			result.Tools = append(result.Tools, Tool{Name: name, Status: "failed", Detail: "setup cancelled"})
			continue
		}
		tool := Tool{Name: name, Status: "missing"}
		toolCtx, cancel := context.WithTimeout(ctx, options.Timeout)
		binary, err := e.lookup(name)
		if errors.Is(err, exec.ErrNotFound) && !options.CheckOnly {
			fmt.Fprintf(progress, "Installing %s...\n", name)
			binary, err = e.install(toolCtx, name)
			tool.Status = "installed"
		} else if err == nil {
			tool.Status = "ready"
		}
		if err == nil {
			tool.Path = binary
			tool.Version, err = e.version(toolCtx, name, binary)
		}
		cancel()
		if err != nil {
			tool.Status = "failed"
			if options.CheckOnly && errors.Is(err, exec.ErrNotFound) {
				tool.Status = "missing"
				tool.Detail = "run pug setup to install missing tools"
			} else {
				tool.Detail = tools.Summarize(err.Error(), detailLimit)
			}
			result.Ready = false
		}
		result.Tools = append(result.Tools, tool)
		fmt.Fprintf(progress, "  %-14s %s", name, tool.Status)
		if tool.Version != "" {
			fmt.Fprintf(progress, "  %s", tool.Version)
		}
		if tool.Detail != "" {
			fmt.Fprintf(progress, "  %s", tool.Detail)
		}
		fmt.Fprintln(progress)
	}
	result.Docker = e.prerequisite(ctx, "docker", []string{"info", "--format", "{{.ServerVersion}}"}, "Install Docker and start its daemon for ZAP or sandbox commands.")
	result.Git = e.prerequisite(ctx, "git", []string{"--version"}, "Install Git to use the sandbox.")
	if options.WithZAP {
		zap := Tool{Name: "zap", Status: "missing", Path: options.ZAPImage}
		if result.Docker.Status != "ready" {
			zap.Detail = "Start Docker, then rerun pug setup --with-zap."
		} else {
			zapCtx, cancel := context.WithTimeout(ctx, options.Timeout)
			inspect := runner.Invocation{Program: "docker", Args: []string{"image", "inspect", options.ZAPImage}}
			r := e.run(zapCtx, inspect)
			if r.Err != nil && !options.CheckOnly && zapCtx.Err() == nil {
				fmt.Fprintln(progress, "Pulling pinned ZAP image...")
				r = e.run(zapCtx, runner.Invocation{Program: "docker", Args: []string{"pull", options.ZAPImage}})
				if r.Err == nil {
					r = e.run(zapCtx, inspect)
				}
			}
			if r.Err == nil {
				zap.Status = "ready"
			} else {
				zap.Detail = "ZAP image unavailable. Check Docker and registry access, then rerun pug setup --with-zap."
			}
			cancel()
		}
		result.ZAP = &zap
		result.Ready = result.Ready && zap.Status == "ready"
	}
	if !result.Ready {
		result.NextStep = "Check the tool errors above, then rerun pug setup."
	}
	return result
}

func nextStep(selected []string) string {
	available := map[string]bool{}
	for _, name := range selected {
		available[name] = true
	}
	checks := []string{}
	for _, check := range scanner.RepositoryChecks {
		if available[scanner.Tools[check]] {
			checks = append(checks, check)
		}
	}
	if len(checks) > 0 {
		selection := ""
		if len(checks) != len(scanner.RepositoryChecks) {
			selection = " --checks " + strings.Join(checks, ",")
		}
		return "pug scan ." + selection + " --output pug-report.json"
	}
	checks = nil
	args := ""
	if available["schemathesis"] {
		checks = append(checks, "api")
		args += " --schema /path/to/openapi.json"
	}
	if available["nuclei"] {
		checks = append(checks, "exposure")
		args += " --templates /path/to/reviewed-templates"
	}
	return "pug app http://127.0.0.1:8000 --allow-active --checks " + strings.Join(checks, ",") + args
}

func (e engine) prerequisite(ctx context.Context, name string, args []string, hint string) Tool {
	tool := Tool{Name: name, Status: "missing", Detail: hint}
	binary, err := e.lookup(name)
	if err != nil {
		return tool
	}
	tool.Path = binary
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := e.run(ctx, runner.Invocation{Program: binary, Args: args})
	if r.Err != nil {
		tool.Status = "unavailable"
		return tool
	}
	tool.Status, tool.Version, tool.Detail = "ready", tools.Summarize(string(r.Stdout), detailLimit), ""
	return tool
}

func (e engine) version(ctx context.Context, name, binary string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r := e.run(ctx, runner.Invocation{Program: binary, Args: tools.VersionArgs(name)})
	if r.Err != nil {
		return "", fmt.Errorf("%s version check failed: %w", name, r.Err)
	}
	if line := tools.VersionLine(r.Stdout, r.Stderr); line != "" {
		return line, nil
	}
	return "", fmt.Errorf("%s returned no version information", name)
}

func currentPlatform() string {
	osName := runtime.GOOS
	if osName == "linux" {
		loaders, _ := filepath.Glob("/lib/ld-musl-*.so.1")
		glibcLoader := map[string]string{"amd64": "/lib64/ld-linux-x86-64.so.2", "arm64": "/lib/ld-linux-aarch64.so.1"}[runtime.GOARCH]
		if _, err := os.Stat(glibcLoader); err != nil && len(loaders) > 0 {
			osName = "linux-musl"
		}
	}
	return osName + "/" + runtime.GOARCH
}

func (e engine) installTool(ctx context.Context, name string) (string, error) {
	if strings.HasPrefix(e.platform, "linux-musl/") {
		return "", fmt.Errorf("automatic installation requires Linux with glibc. Use a Debian or Ubuntu VM, or install %s on PATH", name)
	}
	if name != "schemathesis" {
		return e.installBinary(ctx, name)
	}
	if err := os.MkdirAll(e.home, 0o700); err != nil {
		return "", err
	}
	uv, err := e.lookup("uv")
	if errors.Is(err, exec.ErrNotFound) {
		uv, err = e.installBinary(ctx, "uv")
	}
	if err != nil {
		return "", err
	}
	// Keep Python and tool environments under Pug's home, without project config.
	env := os.Environ()
	for key, value := range map[string]string{
		"UV_CACHE_DIR":          filepath.Join(e.home, "cache"),
		"UV_TOOL_DIR":           filepath.Join(e.home, "python-tools"),
		"UV_TOOL_BIN_DIR":       filepath.Join(e.home, "bin"),
		"UV_PYTHON_INSTALL_DIR": filepath.Join(e.home, "python"),
	} {
		prefix := key + "="
		filtered := []string{}
		for _, entry := range env {
			if !strings.HasPrefix(entry, prefix) {
				filtered = append(filtered, entry)
			}
		}
		env = append(filtered, prefix+value)
	}
	r := e.run(ctx, runner.Invocation{
		Program: uv, Args: []string{"--no-config", "--no-progress", "tool", "install", "--python", "3.12", "--managed-python", "schemathesis==4.33.2"},
		Env: env, Dir: e.home,
	})
	if r.Err != nil {
		return "", fmt.Errorf("Schemathesis installation failed: %w; %s", r.Err, tools.Summarize(string(r.Stderr), detailLimit))
	}
	return filepath.Join(e.home, "bin", "schemathesis"), nil
}

// detailLimit bounds tool output echoed into setup results.
const detailLimit = 300
