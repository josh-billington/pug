// Package scanner adapts external security tools into a common evidence report.
package scanner

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/runner"
	"github.com/josh-billington/pug/internal/tools"
)

//go:embed rules.yml
var rules []byte

var AllChecks = []string{"source", "secrets", "dependencies", "actions", "infra", "image", "api", "exposure", "zap", "pentest"}
var RepositoryChecks = []string{"source", "secrets", "dependencies", "actions", "infra"}

var Tools = map[string]string{
	"source": "opengrep", "secrets": "gitleaks", "dependencies": "trivy",
	"actions": "actionlint", "infra": "trivy", "image": "trivy",
	"api": "schemathesis", "exposure": "nuclei", "zap": "docker",
}

var digestImage = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[a-f0-9]{64}$`)

// notApplicable means the target has nothing for a check to inspect. The check
// completes without running its tool instead of leaving coverage incomplete.
type notApplicable string

func (n notApplicable) Error() string { return string(n) }

func ValidImage(image string) bool { return digestImage.MatchString(image) }

type Options struct {
	Target    string
	Kind      string
	Checks    []string
	Timeout   time.Duration
	Rules     string
	Schema    string
	Templates string
	ZAPImage  string
	Version   string
}

func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse target URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("target must be an absolute http or https URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("target URL must not contain credentials, a query, or a fragment")
	}
	return nil
}

func Validate(options *Options) error {
	if options.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	allowed := map[string]bool{}
	switch options.Kind {
	case "repo":
		for _, name := range RepositoryChecks {
			allowed[name] = true
		}
		path, err := filepath.Abs(options.Target)
		if err != nil {
			return fmt.Errorf("resolve target: %w", err)
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("repository target must be an existing directory")
		}
		options.Target = path
	case "image":
		allowed["image"] = true
		if !ValidImage(options.Target) {
			return fmt.Errorf("image must be pinned as name@sha256:<64 lowercase hex digits>")
		}
	case "app":
		allowed = map[string]bool{"api": true, "exposure": true, "zap": true}
		if err := ValidateURL(options.Target); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown target kind %q", options.Kind)
	}
	if len(options.Checks) == 0 {
		return fmt.Errorf("at least one check is required")
	}
	seen := map[string]bool{}
	for _, check := range options.Checks {
		if !allowed[check] || seen[check] {
			return fmt.Errorf("invalid or repeated %s check %q", options.Kind, check)
		}
		seen[check] = true
	}
	for name, path := range map[string]string{"rules": options.Rules, "schema": options.Schema, "templates": options.Templates} {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("%s must reference an existing local path: %w", name, err)
		}
		if name != "templates" && !info.Mode().IsRegular() {
			return fmt.Errorf("%s must reference a regular file", name)
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", name, err)
		}
		switch name {
		case "rules":
			options.Rules = absolute
		case "schema":
			options.Schema = absolute
		case "templates":
			options.Templates = absolute
		}
	}
	if options.ZAPImage != "" && !ValidImage(options.ZAPImage) {
		return fmt.Errorf("ZAP image must be pinned by sha256 digest")
	}
	return nil
}

func Scan(ctx context.Context, options Options, executor runner.Executor) report.Report {
	r := report.Report{
		SchemaVersion: "1", Version: options.Version, Target: options.Target, StartedAt: time.Now().UTC(),
		Checks: []report.Check{}, NotTested: []report.CoverageGap{},
		Limitations: []string{
			"Completed means the selected tool finished, not that the target is secure.",
			"Scanner rules, vulnerability databases, templates, and tested endpoints limit coverage.",
			"Native scanners run with your user permissions; scan only trusted checkouts or use isolation.",
			"Reports omit source snippets and raw HTTP traffic but may contain sensitive paths, URLs, and messages.",
		},
	}
	if options.Kind == "repo" {
		r.Limitations = append(r.Limitations,
			"Scans inspect the working tree, not Git history or only the PR diff; files may change during a scan.",
			"Bundled source rules are a small starter pack; Actions linting is not a complete workflow security audit.")
	}
	if options.Kind == "app" {
		r.Limitations = append(r.Limitations,
			"Application tests send active requests and can modify application data.",
			"URL validation is not a network sandbox; use trusted schemas/templates and an isolated test environment.",
			"Authentication, business logic, and endpoints absent from the schema or crawl may remain untested.")
	}
	requested := map[string]bool{}
	for _, check := range options.Checks {
		requested[check] = true
		r.Checks = append(r.Checks, runCheck(ctx, options, check, executor))
	}
	r.Finalize(requested, AllChecks)
	return r
}

type plan struct {
	invocation runner.Invocation
	artifact   string
	parser     func([]byte) ([]report.Finding, error)
	accepted   map[int]bool
	container  string
	// mount is a host directory bind-mounted writable into image; files the
	// container writes there may be owned by a uid the host user cannot remove.
	mount string
	image string
}

func buildPlan(options Options, name, temp string) (plan, error) {
	artifact := filepath.Join(temp, "evidence.sarif")
	tool := Tools[name]
	p := plan{
		invocation: runner.Invocation{Program: tool, Dir: temp}, artifact: artifact,
		parser:   func(data []byte) ([]report.Finding, error) { return parseSARIF(data, tool) },
		accepted: map[int]bool{0: true},
	}
	switch name {
	case "secrets":
		// A separate finding exit code keeps scanner errors distinct from discovered leaks.
		p.invocation.Args = []string{"dir", options.Target, "--no-banner", "--redact=100", "--exit-code=10", "--report-format=sarif", "--report-path", artifact}
		p.accepted[10] = true
	case "source":
		config := options.Rules
		if config == "" {
			config = filepath.Join(temp, "rules.yml")
			if err := os.WriteFile(config, rules, 0o600); err != nil {
				return p, fmt.Errorf("write bundled rules: %w", err)
			}
		}
		p.invocation.Args = []string{"scan", "--config", config, "--sarif", "--output", artifact, "--disable-version-check", "--strict", options.Target}
	case "dependencies":
		p.invocation.Args = []string{"fs", "--scanners", "vuln", "--format", "sarif", "--output", artifact, options.Target}
	case "infra":
		p.invocation.Args = []string{"config", "--format", "sarif", "--output", artifact, options.Target}
	case "image":
		p.invocation.Args = []string{"image", "--scanners", "vuln,misconfig", "--format", "sarif", "--output", artifact, options.Target}
	case "actions":
		paths, err := filepath.Glob(filepath.Join(options.Target, ".github", "workflows", "*"))
		if err != nil {
			return p, err
		}
		p.invocation.Dir = options.Target
		p.invocation.Args = []string{"-format", "{{json .}}", "-shellcheck=", "-pyflakes="}
		for _, path := range paths {
			if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
				p.invocation.Args = append(p.invocation.Args, path)
			}
		}
		if len(p.invocation.Args) == 4 {
			return p, notApplicable("no GitHub Actions workflow YAML files found; nothing to lint")
		}
		p.artifact = ""
		p.parser = parseActionlint
		p.accepted[1] = true
	case "api":
		if options.Schema == "" {
			return p, fmt.Errorf("no local OpenAPI schema supplied; use --schema")
		}
		p.artifact = filepath.Join(temp, "junit.xml")
		p.invocation.Args = []string{
			"run", options.Schema, "--url", options.Target, "--checks", "all", "--max-redirects", "0",
			"--workers", "1", "--max-examples", "25", "--rate-limit", "10/s",
			"--report-junit-path", p.artifact, "--no-color",
		}
		p.parser = parseJUnit
		p.accepted[1] = true
	case "exposure":
		if options.Templates == "" {
			return p, fmt.Errorf("no reviewed local Nuclei templates supplied; use --templates")
		}
		p.artifact = ""
		p.invocation.Args = []string{"-u", options.Target, "-t", options.Templates, "-jsonl", "-silent", "-disable-update-check", "-no-interactsh", "-disable-redirects", "-type", "http", "-rate-limit", "5", "-concurrency", "1", "-omit-raw"}
		p.parser = parseNuclei
	case "zap":
		if options.ZAPImage == "" {
			return p, fmt.Errorf("no locally installed digest-pinned ZAP image supplied; use --zap-image")
		}
		work := filepath.Join(temp, "zap")
		if err := os.Mkdir(work, 0o777); err != nil {
			return p, fmt.Errorf("create ZAP report directory: %w", err)
		}
		// Only the nested directory is writable by the container; its host parent remains private.
		if err := os.Chmod(work, 0o777); err != nil {
			return p, err
		}
		container := "pug-zap-" + filepath.Base(temp)
		p.artifact = filepath.Join(work, "report.json")
		p.invocation.Args = []string{
			"run", "--rm", "--pull=never", "--name", container,
			"--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=1g", "--cpus=1", "--pids-limit=256",
			"--mount", "type=bind,src=" + work + ",dst=/zap/wrk", options.ZAPImage,
			"zap-full-scan.py", "-t", options.Target, "-J", "report.json", "-m", "1",
		}
		p.container = container
		p.mount, p.image = work, options.ZAPImage
		p.accepted[1], p.accepted[2] = true, true
		p.parser = parseZAP
	default:
		return p, fmt.Errorf("unsupported check %q", name)
	}
	return p, nil
}

func runCheck(ctx context.Context, options Options, name string, executor runner.Executor) (check report.Check) {
	started := time.Now()
	check = report.Check{
		Name: name, Tool: Tools[name], Status: "failed", StartedAt: started.UTC(), ExitCode: -1,
		Findings: []report.Finding{},
	}
	defer func() { check.DurationMS = time.Since(started).Milliseconds() }()
	temp, err := os.MkdirTemp("", "pug-*")
	if err != nil {
		check.Reason = "cannot create private scanner workspace"
		return check
	}
	var p plan
	defer func() {
		if err := cleanupWorkspace(ctx, executor, temp, p); err != nil {
			check.Reason = joinReason(check.Reason, "warning: could not remove scanner workspace "+temp+": "+err.Error())
		}
	}()
	p, err = buildPlan(options, name, temp)
	var skip notApplicable
	if errors.As(err, &skip) {
		check.Status, check.ExitCode, check.Reason = "completed", 0, skip.Error()
		return check
	}
	if err != nil {
		check.Status, check.Reason = "skipped", err.Error()
		return check
	}
	check.Command = append([]string{p.invocation.Program}, p.invocation.Args...)
	scanCtx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	versionCtx, versionCancel := context.WithTimeout(scanCtx, 5*time.Second)
	version := executor.Run(versionCtx, runner.Invocation{Program: p.invocation.Program, Args: tools.VersionArgs(p.invocation.Program), Dir: temp})
	versionCancel()
	if errors.Is(version.Err, exec.ErrNotFound) {
		check.Status, check.Reason = "unavailable", "executable not found on PATH: "+p.invocation.Program
		return check
	}
	if version.Err == nil && !version.Truncated && len(version.Stdout) <= 4096 && len(version.Stderr) <= 4096 {
		check.Version = tools.VersionLine(version.Stdout, version.Stderr)
	}
	if p.container != "" {
		defer func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cleanupCancel()
			if err := runner.RemoveContainer(cleanupCtx, executor, p.container); err != nil {
				check.Status = "failed"
				check.Reason = joinReason(check.Reason, err.Error())
			}
		}()
	}
	result := executor.Run(scanCtx, p.invocation)
	check.DurationMS = time.Since(started).Milliseconds()
	check.ExitCode = result.ExitCode
	if scanCtx.Err() != nil {
		check.Reason = "scanner cancelled or timed out; coverage is incomplete"
		return check
	}
	if !p.accepted[result.ExitCode] || result.Truncated || (result.Err != nil && result.ExitCode == 0) {
		check.Reason = fmt.Sprintf("scanner failed (exit %d); check tool installation and run the tool directly for diagnostics", result.ExitCode)
		return check
	}
	data := result.Stdout
	if p.artifact != "" {
		info, err := os.Lstat(p.artifact)
		if err != nil || !info.Mode().IsRegular() || info.Size() > runner.MaxOutput {
			check.Reason = "scanner did not produce a regular report within the 16 MiB limit"
			return check
		}
		file, err := os.Open(p.artifact)
		if err != nil {
			check.Reason = "cannot read scanner report"
			return check
		}
		data, err = io.ReadAll(io.LimitReader(file, runner.MaxOutput+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || len(data) > runner.MaxOutput {
			check.Reason = "cannot read scanner report within the 16 MiB limit"
			return check
		}
	}
	check.EvidenceSHA256 = report.Digest(data)
	findings, err := p.parser(data)
	// Parsers leave findings unidentified; fingerprints include the check name.
	for _, finding := range findings {
		finding.Check = name
		finding.Identify()
		check.Findings = append(check.Findings, finding)
	}
	if err != nil {
		// Parser errors contain metadata only, never raw scanner output or secret values.
		check.Reason = "invalid or incomplete scanner report: " + err.Error()
		return check
	}
	if result.ExitCode != 0 && len(findings) == 0 {
		check.Reason = "scanner returned a finding exit code but its report has no findings"
		return check
	}
	check.Status = "completed"
	return check
}

// cleanupWorkspace removes the private scanner workspace. A container writing
// into a bind mount can leave entries owned by its own uid (ZAP runs as uid 1000)
// that the host user cannot delete, so when host removal fails and the plan
// used a mount, a short-lived container from the same image, running as the
// image's default user (the writer), empties the mounted directory first. Only
// the nested mount is exposed; the private parent is never mounted or chmodded.
func cleanupWorkspace(ctx context.Context, executor runner.Executor, temp string, p plan) error {
	err := os.RemoveAll(temp)
	if err == nil || p.mount == "" || p.image == "" {
		return err
	}
	if purgeErr := purgeMount(ctx, executor, p.image, p.mount, "pug-clean-"+filepath.Base(temp)); purgeErr != nil {
		return fmt.Errorf("%w; container cleanup fallback failed: %v", err, purgeErr)
	}
	return os.RemoveAll(temp)
}

// purgeCommand restores owner access to each directory before find descends
// into it (the host-owned mount root itself cannot be chmodded, which stops
// chmod -R early), deletes everything below the mount depth-first, then
// verifies the mount is empty because busybox find -delete exits 0 on failure.
const purgeCommand = `find /pug-clean -mindepth 1 -type d -exec chmod u+rwx {} \; 2>/dev/null; ` +
	`find /pug-clean -mindepth 1 -delete; [ -z "$(ls -A /pug-clean)" ]`

func purgeMount(ctx context.Context, executor runner.Executor, image, dir, container string) error {
	// Runs during cleanup, so it must not inherit a cancelled scan context; it is bounded instead.
	purgeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	result := executor.Run(purgeCtx, runner.Invocation{Program: "docker", Args: []string{
		"run", "--rm", "--pull=never", "--name", container, "--network=none",
		"--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=128m", "--cpus=0.5", "--pids-limit=32",
		"--mount", "type=bind,src=" + dir + ",dst=/pug-clean", "--entrypoint", "/bin/sh", image,
		"-c", purgeCommand,
	}})
	removeErr := runner.RemoveContainer(purgeCtx, executor, container)
	if purgeCtx.Err() != nil {
		return fmt.Errorf("cleanup container timed out")
	}
	if result.Err != nil || result.ExitCode != 0 {
		return fmt.Errorf("cleanup container exited %d", result.ExitCode)
	}
	return removeErr
}

// joinReason appends note to an existing reason without a dangling separator.
func joinReason(reason, note string) string {
	if reason == "" {
		return note
	}
	return reason + "; " + note
}
