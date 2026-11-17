package scanner

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

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/rules"
	"github.com/josh-billington/pug/internal/runner"
)

type executorFunc func(context.Context, runner.Invocation) runner.Result

func (f executorFunc) Run(ctx context.Context, i runner.Invocation) runner.Result { return f(ctx, i) }

func TestScanCoverage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result runner.Result
		data   string
		status string
	}{
		{name: "missing tool", result: runner.Result{Err: exec.ErrNotFound, ExitCode: -1}, status: "unavailable"},
		{name: "runtime failure", result: runner.Result{Err: errors.New("failed"), ExitCode: 2}, status: "failed"},
		{name: "invalid report", result: runner.Result{}, data: `{}`, status: "failed"},
		{name: "truncated output", result: runner.Result{Truncated: true}, status: "failed"},
		{name: "clean scan", result: runner.Result{}, data: `{"version":"2.1.0","runs":[{"results":[]}]}`, status: "completed"},
		{name: "partial parse", result: runner.Result{}, data: `{"version":"2.1.0","runs":[{"invocations":[{"toolExecutionNotifications":[{"level":"warning"}]}],"results":[]}]}`, status: "completed"},
		{name: "finding exit without evidence", result: runner.Result{ExitCode: 10}, data: `{"version":"2.1.0","runs":[{"results":[]}]}`, status: "failed"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
				if len(i.Args) == 1 {
					if tt.status == "unavailable" {
						return tt.result
					}
					return runner.Result{Stdout: []byte("test-version")}
				}
				for n, arg := range i.Args {
					if arg == "--report-path" {
						if err := os.WriteFile(i.Args[n+1], []byte(tt.data), 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				return tt.result
			})
			r := Scan(t.Context(), Options{Target: t.TempDir(), Kind: "repo", Checks: []string{"secrets"}, Timeout: time.Second}, executor)
			if r.Checks[0].Status != tt.status || r.Complete != (tt.status == "completed") {
				t.Fatalf("incorrect coverage: %+v", r)
			}
			if tt.name == "partial parse" && !strings.Contains(r.Checks[0].Reason, "partial") {
				t.Fatalf("partial coverage not explained: %q", r.Checks[0].Reason)
			}
			if len(r.NotTested) < len(AllChecks)-1 {
				t.Fatalf("missing coverage gaps: %+v", r.NotTested)
			}
		})
	}
}

func TestValidateTargets(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"ftp://host", "localhost:8000", "http://user:password@host", "http://host/?token=secret", "http://host/#fragment"} {
		t.Run(raw, func(t *testing.T) {
			if err := ValidateURL(raw); err == nil {
				t.Fatal("unsafe target accepted")
			}
		})
	}
	if err := ValidateURL("http://127.0.0.1:8000/api"); err != nil {
		t.Fatal(err)
	}
	if ValidImage("alpine:latest") || !ValidImage("alpine@sha256:"+strings.Repeat("a", 64)) {
		t.Fatal("image digest validation failed")
	}
	options := Options{Kind: "repo", Target: t.TempDir(), Checks: []string{"secrets", "secrets"}, Timeout: time.Second}
	if err := Validate(&options); err == nil {
		t.Fatal("duplicate check accepted")
	}
}

func TestActionsWithoutWorkflowsIsNotIncomplete(t *testing.T) {
	t.Parallel()
	executor := executorFunc(func(context.Context, runner.Invocation) runner.Result {
		t.Error("actionlint ran without workflows")
		return runner.Result{Err: exec.ErrNotFound, ExitCode: -1}
	})
	r := Scan(t.Context(), Options{Target: t.TempDir(), Kind: "repo", Checks: []string{"actions"}, Timeout: time.Second}, executor)
	if check := r.Checks[0]; check.Status != "completed" || check.ExitCode != 0 || !r.Complete || !strings.Contains(check.Reason, "no GitHub Actions workflow") {
		t.Fatalf("workflow-free repository left coverage incomplete: %+v", r)
	}
}

func TestScanRecordsStderrVersionAndIdentifiesFindingsOnce(t *testing.T) {
	t.Parallel()
	sarif := `{"version":"2.1.0","runs":[{"results":[{"ruleId":"token","message":{"text":"leak"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"config"},"region":{"startLine":2}}}]}]}]}`
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		if len(i.Args) == 1 {
			return runner.Result{Stderr: []byte("\x1b[1mgitleaks v8.0.0\x1b[0m\n")}
		}
		for n, arg := range i.Args {
			if arg == "--report-path" {
				if err := os.WriteFile(i.Args[n+1], []byte(sarif), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return runner.Result{ExitCode: 10}
	})
	r := Scan(t.Context(), Options{Target: t.TempDir(), Kind: "repo", Checks: []string{"secrets"}, Timeout: time.Second}, executor)
	check := r.Checks[0]
	if check.Status != "completed" || check.Version != "gitleaks v8.0.0" || len(check.Findings) != 1 {
		t.Fatalf("unexpected check: %+v", check)
	}
	finding := check.Findings[0]
	want := finding
	want.Identify()
	if finding.Check != "secrets" || finding.Fingerprint == "" || finding.Fingerprint != want.Fingerprint {
		t.Fatalf("finding fingerprint inconsistent with its check: %+v", finding)
	}
}

func TestJoinReason(t *testing.T) {
	t.Parallel()
	if got := joinReason("", "cleanup failed"); got != "cleanup failed" {
		t.Fatalf("empty reason = %q", got)
	}
	if got := joinReason("timed out", "cleanup failed"); got != "timed out; cleanup failed" {
		t.Fatalf("joined reason = %q", got)
	}
}

func TestSourceRunsBesideComposedRulesForStableRuleIDs(t *testing.T) {
	temp := t.TempDir()
	custom := filepath.Join(t.TempDir(), "team", "my-rules.yml")
	if err := os.MkdirAll(filepath.Dir(custom), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(custom, []byte("rules:\n  - id: team-rule\n    languages: [go]\n    severity: INFO\n    message: m\n    pattern: f()\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := Options{Kind: "repo", Target: t.TempDir(), Checks: []string{"source"}, Timeout: time.Second,
		Rules: []rules.Spec{{Kind: rules.StarterSpec}, {Kind: rules.PathSpec, Path: custom}}}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	p, err := buildPlan(options, "source", temp)
	if err != nil {
		t.Fatal(err)
	}
	if p.invocation.Dir != temp {
		t.Fatalf("OpenGrep must run in the rules directory, got %q", p.invocation.Dir)
	}
	if !slices.Contains(p.invocation.Args, "rules.yml") || slices.Contains(p.invocation.Args, "--strict") {
		t.Fatalf("config must be passed by base name, without --strict: %v", p.invocation.Args)
	}
	config, err := os.ReadFile(filepath.Join(temp, "rules.yml"))
	if err != nil || !strings.Contains(string(config), "id: team-rule") || !strings.Contains(string(config), "id: javascript-eval") {
		t.Fatalf("composed config lacks the selected rules: %v\n%s", err, config)
	}
	if p.rules == nil || p.rules.SHA256 != report.Digest(config) || !slices.Equal(p.rules.Specs, []string{"starter", custom}) {
		t.Fatalf("provenance does not describe the config: %+v", p.rules)
	}
}

func installFakePack(t *testing.T, home string, pack string, files map[string]string) {
	t.Helper()
	dir := rules.Dir(home, pack)
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSourceCheckWithRulePacks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	pack := "fixture"
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"fixture.python.eval","defaultConfiguration":{"level":"error"}}]}},` +
		`"results":[{"ruleId":"fixture.python.eval","message":{"text":"eval"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]}]}]}`
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		if n := slices.Index(i.Args, "--output"); n >= 0 {
			if err := os.WriteFile(i.Args[n+1], []byte(sarif), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return runner.Result{}
	})
	options := Options{Kind: "repo", Target: t.TempDir(), Checks: []string{"source"}, Timeout: time.Second, Rules: []rules.Spec{{Kind: rules.PackSpec, Name: pack}}}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	check := Scan(t.Context(), options, executor).Checks[0]
	if check.Status != "skipped" || !strings.Contains(check.Reason, "run: pug rules install fixture") {
		t.Fatalf("missing pack did not skip the check: %+v", check)
	}

	installFakePack(t, home, pack, map[string]string{
		"python/eval.yaml":     "rules:\n  - id: eval\n    languages: [python]\n    severity: ERROR\n    message: eval\n    pattern: eval(...)\n",
		"configs/default.list": "python/eval.yaml:eval\npython/gone.yaml:gone\n",
	})
	options = Options{Kind: "repo", Target: options.Target, Checks: []string{"source"}, Timeout: time.Second, Rules: []rules.Spec{{Kind: rules.PackSpec, Name: pack}}}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	check = Scan(t.Context(), options, executor).Checks[0]
	if check.Status != "completed" || len(check.Findings) != 1 || check.Findings[0].Severity != "high" {
		t.Fatalf("pack scan did not complete with its finding: %+v", check)
	}
	if check.Rules == nil || check.Rules.Packs["fixture"] != "" || len(check.Rules.Unresolved) != 1 || !strings.Contains(check.Reason, "skipped 1 profile entries") {
		t.Fatalf("provenance or unresolved entries not reported: %+v reason=%q", check.Rules, check.Reason)
	}
}
