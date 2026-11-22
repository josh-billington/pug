package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/rules"
	"github.com/josh-billington/pug/internal/runner"
)

type executorFunc func(context.Context, runner.Invocation) runner.Result

func (f executorFunc) Run(ctx context.Context, i runner.Invocation) runner.Result { return f(ctx, i) }

func fakeGitleaks(t *testing.T, version runner.Result, sarif string, result runner.Result) executorFunc {
	t.Helper()
	return func(_ context.Context, i runner.Invocation) runner.Result {
		if len(i.Args) == 1 {
			return version
		}
		for n, arg := range i.Args {
			if arg == "--report-path" {
				if err := os.WriteFile(i.Args[n+1], []byte(sarif), 0o600); err != nil {
					t.Error(err)
				}
			}
		}
		return result
	}
}

func TestScanCoverage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		result   runner.Result
		data     string
		status   string
		findings int
		hidden   string
	}{
		{name: "missing tool", result: runner.Result{Err: exec.ErrNotFound, ExitCode: -1}, status: "unavailable"},
		{name: "runtime failure", result: runner.Result{Err: errors.New("failed"), ExitCode: 2}, status: "failed"},
		{name: "invalid report", result: runner.Result{}, data: `{}`, status: "failed"},
		{name: "truncated output", result: runner.Result{Truncated: true}, status: "failed"},
		{name: "clean scan", result: runner.Result{}, data: `{"version":"2.1.0","runs":[{"results":[]}]}`, status: "completed"},
		{name: "partial parse", result: runner.Result{}, data: `{"version":"2.1.0","runs":[{"invocations":[{"toolExecutionNotifications":[{"level":"warning"}]}],"results":[]}]}`, status: "completed"},
		{name: "warning notification beside a result", result: runner.Result{}, data: `{"version":"2.1.0","runs":[{"invocations":[{"executionSuccessful":true,"toolExecutionNotifications":[` +
			`{"level":"warning","message":{"text":"Syntax error at line bad.rb:2: SECRET_SOURCE_TEXT"}}]}],` +
			`"results":[{"ruleId":"token","message":{"text":"leak"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"config"},"region":{"startLine":2}}}]}]}]}`,
			status: "completed", findings: 1, hidden: "SECRET_SOURCE_TEXT"},
		{name: "finding exit without evidence", result: runner.Result{ExitCode: 10}, data: `{"version":"2.1.0","runs":[{"results":[]}]}`, status: "failed"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			version := runner.Result{Stdout: []byte("test-version")}
			if tt.status == "unavailable" {
				version = tt.result
			}
			executor := fakeGitleaks(t, version, tt.data, tt.result)
			r := Scan(t.Context(), Options{Target: t.TempDir(), Kind: "repo", Checks: []string{"secrets"}, Timeout: time.Second}, executor)
			if r.Checks[0].Status != tt.status || r.Complete != (tt.status == "completed") {
				t.Fatalf("incorrect coverage: %+v", r)
			}
			if len(r.Checks[0].Findings) != tt.findings {
				t.Fatalf("findings = %+v, want %d", r.Checks[0].Findings, tt.findings)
			}
			if tt.hidden != "" && strings.Contains(r.Checks[0].Reason, tt.hidden) {
				t.Fatalf("reason quotes scanner notification text: %q", r.Checks[0].Reason)
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
	executor := fakeGitleaks(t, runner.Result{Stderr: []byte("\x1b[1mgitleaks v8.0.0\x1b[0m\n")}, sarif, runner.Result{ExitCode: 10})
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

func TestScanReportsFileLocationsRelativeToTheTarget(t *testing.T) {
	t.Parallel()
	target := t.TempDir()
	inside := filepath.Join(target, "site", "lib", "site.ts")
	uris := []string{inside, "file://" + filepath.ToSlash(inside), "config/app.env", "/elsewhere/key.pem"}
	var results []string
	for _, uri := range uris {
		results = append(results, `{"ruleId":"token","message":{"text":"leak"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":`+
			strconv.Quote(uri)+`},"region":{"startLine":3}}}]}`)
	}
	sarif := `{"version":"2.1.0","runs":[{"results":[` + strings.Join(results, ",") + `]}]}`
	executor := fakeGitleaks(t, runner.Result{Stdout: []byte("gitleaks 8")}, sarif, runner.Result{ExitCode: 10})
	r := Scan(t.Context(), Options{Target: target, Kind: "repo", Checks: []string{"secrets"}, Timeout: time.Second}, executor)
	var got []string
	for _, finding := range r.Checks[0].Findings {
		got = append(got, finding.Location)
	}
	want := []string{"site/lib/site.ts", "site/lib/site.ts", "config/app.env", "/elsewhere/key.pem"}
	if !slices.Equal(got, want) {
		t.Fatalf("locations = %q, want %q", got, want)
	}
	if r.Checks[0].Findings[0].Fingerprint != r.Checks[0].Findings[1].Fingerprint {
		t.Fatal("absolute path and file URI to one file fingerprint differently")
	}
}

func TestSourceRunsBesideComposedRulesForStableRuleIDs(t *testing.T) {
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
	var config []byte
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		n := slices.Index(i.Args, "--config")
		if n < 0 {
			return runner.Result{Stdout: []byte("opengrep 1.0.0")}
		}
		path := i.Args[n+1]
		if !filepath.IsAbs(path) {
			path = filepath.Join(i.Dir, path)
		}
		var err error
		if config, err = os.ReadFile(path); err != nil {
			t.Errorf("OpenGrep cannot read its config: %v", err)
		}
		if out := slices.Index(i.Args, "--output"); out >= 0 {
			if err := os.WriteFile(i.Args[out+1], []byte(`{"version":"2.1.0","runs":[{"results":[]}]}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return runner.Result{}
	})
	check := Scan(t.Context(), options, executor).Checks[0]
	if check.Status != "completed" {
		t.Fatalf("source check did not complete: %+v", check)
	}
	for _, id := range []string{"team-rule", "javascript-eval"} {
		if !strings.Contains(string(config), "id: "+id) {
			t.Fatalf("composed config lacks %s:\n%s", id, config)
		}
	}
	if check.Rules == nil || check.Rules.SHA256 != report.Digest(config) || !slices.Equal(check.Rules.Specs, []string{"starter", custom}) {
		t.Fatalf("provenance does not describe the config: %+v", check.Rules)
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
	installFakePack(t, home, pack, map[string]string{
		"python/eval.yaml":     "rules:\n  - id: eval\n    languages: [python]\n    severity: ERROR\n    message: eval\n    pattern: eval(...)\n",
		"configs/default.list": "python/eval.yaml:eval\npython/gone.yaml:gone\n",
	})
	options := Options{Kind: "repo", Target: t.TempDir(), Checks: []string{"source"}, Timeout: time.Second, Rules: []rules.Spec{{Kind: rules.PackSpec, Name: pack}}}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	check := Scan(t.Context(), options, executor).Checks[0]
	if check.Status != "completed" || len(check.Findings) != 1 || check.Findings[0].Severity != "high" {
		t.Fatalf("pack scan did not complete with its finding: %+v", check)
	}
	if check.Rules == nil || check.Rules.Packs["fixture"] != "" || len(check.Rules.Unresolved) != 1 || !strings.Contains(check.Reason, "skipped 1 profile entries") {
		t.Fatalf("provenance or unresolved entries not reported: %+v reason=%q", check.Rules, check.Reason)
	}
}

func TestSourceRunsTheSelectedPackProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	rule := func(id string) string {
		return "  - id: " + id + "\n    languages: [python]\n    severity: ERROR\n    message: " + id + "\n    pattern: " + id + "(...)\n"
	}
	installFakePack(t, home, "fixture", map[string]string{
		"python/eval.yaml":     "rules:\n" + rule("eval") + rule("eval-in-loop"),
		"python/exec.yaml":     "rules:\n" + rule("exec"),
		"configs/default.list": "python/eval.yaml:eval\n",
		"configs/audit.list":   "python/exec.yaml:exec\npython/eval.yaml:eval-in-loop\n",
	})
	specs, err := rules.ParseSpecs([]string{"fixture:audit"})
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Kind: "repo", Target: t.TempDir(), Checks: []string{"source"}, Timeout: time.Second, Rules: specs}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	var config struct {
		Rules []struct {
			ID string `yaml:"id"`
		} `yaml:"rules"`
	}
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		n := slices.Index(i.Args, "--config")
		if n < 0 {
			return runner.Result{Stdout: []byte("opengrep 1.0.0")}
		}
		path := i.Args[n+1]
		if !filepath.IsAbs(path) {
			path = filepath.Join(i.Dir, path)
		}
		data, err := os.ReadFile(path)
		if err == nil {
			err = yaml.Unmarshal(data, &config)
		}
		if err != nil {
			t.Errorf("read composed config: %v", err)
		}
		if out := slices.Index(i.Args, "--output"); out >= 0 {
			if err := os.WriteFile(i.Args[out+1], []byte(`{"version":"2.1.0","runs":[{"results":[]}]}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return runner.Result{}
	})
	check := Scan(t.Context(), options, executor).Checks[0]
	if check.Status != "completed" {
		t.Fatalf("profile scan did not complete: %+v", check)
	}
	var got []string
	for _, rule := range config.Rules {
		got = append(got, rule.ID)
	}
	slices.Sort(got)
	if want := []string{"fixture.python.eval.eval-in-loop", "fixture.python.exec"}; !slices.Equal(got, want) {
		t.Fatalf("composed rules = %v, want the audit profile %v", got, want)
	}
}

func TestSecretsHistoryReportsCommitsWithoutSecretValues(t *testing.T) {
	t.Parallel()
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := "ghp_" + "R8fKq2LmZx7Vb3Nc9Td4Wy6Hs1Pj5Ae0Gu2K"
	line := `{"SourceMetadata":{"Data":{"Git":{"commit":"1a737cb499e0cd6bedcd19580965340f08df2d2d","file":"old.txt","email":"dev <dev@example.com>","line":1}}},` +
		`"DetectorName":"Github","Verified":false,"Raw":"` + secret + `","RawV2":"` + secret + `","Redacted":"` + secret + `","ExtraData":{"token":"` + secret + `"}}` + "\n"
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		if len(i.Args) == 1 {
			return runner.Result{Stdout: []byte("trufflehog 3.99.7\n")}
		}
		return runner.Result{ExitCode: 183, Stdout: []byte(line)}
	})
	r := Scan(t.Context(), Options{Target: repo, Kind: "repo", Checks: []string{"secrets-history"}, Timeout: time.Second}, executor)
	check := r.Checks[0]
	if check.Status != "completed" || check.Tool != "trufflehog" || len(check.Findings) != 1 {
		t.Fatalf("unexpected check: %+v", check)
	}
	for _, flag := range []string{"--no-verification", "--no-update", "--json", "--exclude-detectors=URI"} {
		if !slices.Contains(check.Command, flag) {
			t.Fatalf("command lacks %s: %v", flag, check.Command)
		}
	}
	finding := check.Findings[0]
	if finding.Rule != "Github" || finding.Location != "old.txt" || finding.Line != 1 || finding.Severity != "high" ||
		!strings.Contains(finding.Message, "1a737cb499e0cd6bedcd19580965340f08df2d2d") {
		t.Fatalf("finding lost its history location: %+v", finding)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || strings.Contains(string(data), "dev@example.com") {
		t.Fatalf("report exposes secret or committer: %s", data)
	}
}

func TestSecretsHistoryNeedsRepositoryRoot(t *testing.T) {
	t.Parallel()
	executor := executorFunc(func(context.Context, runner.Invocation) runner.Result {
		t.Error("trufflehog ran outside a repository root")
		return runner.Result{}
	})
	r := Scan(t.Context(), Options{Target: t.TempDir(), Kind: "repo", Checks: []string{"secrets-history"}, Timeout: time.Second}, executor)
	if check := r.Checks[0]; check.Status != "skipped" || r.Complete || !strings.Contains(check.Reason, ".git") {
		t.Fatalf("non-repository target was not reported as untested: %+v", r)
	}
}

func TestPortScanReportsOnlyUnexpectedPorts(t *testing.T) {
	t.Parallel()
	var scanEnv, versionEnv []string
	stdout := `{"ip":"192.0.2.10","port":22,"protocol":"tcp"}` + "\n" +
		`{"ip":"192.0.2.10","port":8080,"protocol":"tcp"}` + "\n" +
		`{"ip":"192.0.2.10","port":8080,"protocol":"tcp"}` + "\n"
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		if len(i.Args) == 1 {
			versionEnv = i.Env
			return runner.Result{Stderr: []byte("  __\n[INF] Current Version: 2.7.0\n")}
		}
		scanEnv = i.Env
		return runner.Result{Stdout: []byte(stdout)}
	})
	options := Options{Kind: "net", Target: "192.0.2.10", Checks: []string{"ports"}, Ports: "1-1024", Expect: []int{22}, Timeout: time.Second}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	r := Scan(t.Context(), options, executor)
	check := r.Checks[0]
	if check.Status != "completed" || !r.Complete || check.Tool != "naabu" || check.Version != "[INF] Current Version: 2.7.0" {
		t.Fatalf("unexpected check: %+v", check)
	}
	if len(check.Findings) != 1 || check.Findings[0].Location != "192.0.2.10:8080/tcp" || check.Findings[0].Severity != "medium" {
		t.Fatalf("want one unexpected-port finding: %+v", check.Findings)
	}
	for _, flag := range []string{"-s", "-Pn", "-duc", "-no-stdin", "1-1024,22"} {
		if !slices.Contains(check.Command, flag) {
			t.Fatalf("command lacks %s: %v", flag, check.Command)
		}
	}
	for _, env := range [][]string{versionEnv, scanEnv} {
		for _, want := range []string{"HOME=" + os.TempDir(), "XDG_CONFIG_HOME=" + os.TempDir(), "DISABLE_CLOUD_UPLOAD=true"} {
			if !slices.ContainsFunc(env, func(entry string) bool { return strings.HasPrefix(entry, want) }) {
				t.Fatalf("naabu environment lacks %s: %v", want, env)
			}
		}
	}
}

func TestPortScanWithoutExpectedPortIsIncomplete(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ name, stdout, reason string }{
		{name: "host down or filtered", stdout: "", reason: "no expected port"},
		{name: "other address", stdout: `{"ip":"192.0.2.99","port":22,"protocol":"tcp"}` + "\n", reason: "outside the target"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
				return runner.Result{Stdout: []byte(tt.stdout)}
			})
			r := Scan(t.Context(), Options{Kind: "net", Target: "192.0.2.10", Checks: []string{"ports"}, Ports: "1-1024", Expect: []int{22}, Timeout: time.Second}, executor)
			if check := r.Checks[0]; check.Status != "failed" || r.Complete || !strings.Contains(check.Reason, tt.reason) {
				t.Fatalf("silent scan was reported as clean: %+v", check)
			}
		})
	}
}

func TestValidatePortScanTargets(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, target, ports string
		expect              []int
	}{
		{name: "hostname", target: "example.com", ports: "80", expect: []int{80}},
		{name: "CIDR", target: "192.0.2.0/24", ports: "80", expect: []int{80}},
		{name: "unspecified", target: "0.0.0.0", ports: "80", expect: []int{80}},
		{name: "multicast", target: "224.0.0.1", ports: "80", expect: []int{80}},
		{name: "IPv6 zone", target: "fe80::1%en0", ports: "80", expect: []int{80}},
		{name: "mapped unspecified", target: "::ffff:0.0.0.0", ports: "80", expect: []int{80}},
		{name: "no ports", target: "192.0.2.10", expect: []int{80}},
		{name: "port too large", target: "192.0.2.10", ports: "1-65536", expect: []int{80}},
		{name: "reversed range", target: "192.0.2.10", ports: "90-80", expect: []int{80}},
		{name: "flag injection", target: "192.0.2.10", ports: "80,-passive", expect: []int{80}},
		{name: "no expected port", target: "192.0.2.10", ports: "80"},
		{name: "bad expected port", target: "192.0.2.10", ports: "80", expect: []int{0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			options := Options{Kind: "net", Target: tt.target, Checks: []string{"ports"}, Ports: tt.ports, Expect: tt.expect, Timeout: time.Second}
			if err := Validate(&options); err == nil {
				t.Fatalf("unsafe port scan accepted: %+v", options)
			}
		})
	}
	for raw, want := range map[string]string{"2001:db8::0:1": "2001:db8::1", "::ffff:192.0.2.10": "192.0.2.10"} {
		options := Options{Kind: "net", Target: raw, Checks: []string{"ports"}, Ports: "22,80-90", Expect: []int{22}, Timeout: time.Second}
		if err := Validate(&options); err != nil || options.Target != want {
			t.Fatalf("valid target %s rejected or not normalized: %q, %v", raw, options.Target, err)
		}
	}
}

func envHasToken(env []string) bool {
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN":
			return true
		}
	}
	return false
}

func TestWorkflowAuditReportsRelativeFindingsOffline(t *testing.T) {
	t.Setenv("GH_TOKEN", "gh-secret")
	t.Setenv("GITHUB_TOKEN", "github-secret")
	t.Setenv("ZIZMOR_GITHUB_TOKEN", "zizmor-secret")
	target := t.TempDir()
	workflow := filepath.Join(target, ".github", "workflows", "ci.yml")
	sarif := `{"version":"2.1.0","runs":[{"results":[{"ruleId":"zizmor/template-injection","level":"error","message":{"text":"code injection via template expansion"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":` + strconv.Quote(workflow) + `},"region":{"startLine":8}}}]}]}]}`
	var scanArgs, scanEnv []string
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		if envHasToken(i.Env) {
			t.Errorf("zizmor env keeps a GitHub token: %q", i.Env)
		}
		if slices.Equal(i.Args, []string{"--version"}) {
			return runner.Result{Stdout: []byte("zizmor 1.32.0\n")}
		}
		scanArgs, scanEnv = append([]string(nil), i.Args...), append([]string(nil), i.Env...)
		return runner.Result{Stdout: []byte(sarif)}
	})
	r := Scan(t.Context(), Options{Target: target, Kind: "repo", Checks: []string{"workflows"}, Timeout: time.Second}, executor)
	check := r.Checks[0]
	if !r.Complete || check.Status != "completed" || check.Tool != "zizmor" || len(check.Findings) != 1 {
		t.Fatalf("workflow audit: %+v", check)
	}
	finding := check.Findings[0]
	if finding.Rule != "zizmor/template-injection" || finding.Severity != "high" || finding.Location != ".github/workflows/ci.yml" || finding.Line != 8 {
		t.Fatalf("finding: %+v", finding)
	}
	if !slices.Equal(scanArgs, []string{"--offline", "--format=sarif", target}) || slices.Contains(scanArgs, "--persona") || slices.Contains(scanArgs, "--pedantic") {
		t.Fatalf("zizmor args = %q", scanArgs)
	}
	if len(scanEnv) == 0 || envHasToken(scanEnv) {
		t.Fatalf("scan env = %q", scanEnv)
	}
	var out strings.Builder
	if err := report.Write(&out, r, "sarif"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			AutomationDetails struct{ ID string } `json:"automationDetails"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || doc.Runs[0].AutomationDetails.ID != "pug/workflows/" {
		t.Fatalf("sarif runs = %+v", doc.Runs)
	}
}

func TestWorkflowsWithoutInputsCompletes(t *testing.T) {
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		if slices.Equal(i.Args, []string{"--version"}) {
			return runner.Result{Stdout: []byte("zizmor 1.32.0\n")}
		}
		return runner.Result{ExitCode: 3, Err: errors.New("exit status 3")}
	})
	r := Scan(t.Context(), Options{Target: t.TempDir(), Kind: "repo", Checks: []string{"workflows"}, Timeout: time.Second}, executor)
	check := r.Checks[0]
	if !r.Complete || check.Status != "completed" || check.ExitCode != 0 || len(check.Findings) != 0 || !strings.Contains(check.Reason, "nothing to audit") {
		t.Fatalf("empty repository: %+v", check)
	}
}

func TestWorkflowErrorFailsTheCheck(t *testing.T) {
	executor := executorFunc(func(_ context.Context, i runner.Invocation) runner.Result {
		if slices.Equal(i.Args, []string{"--version"}) {
			return runner.Result{Stdout: []byte("zizmor 1.32.0\n")}
		}
		return runner.Result{ExitCode: 1, Err: errors.New("exit status 1")}
	})
	r := Scan(t.Context(), Options{Target: t.TempDir(), Kind: "repo", Checks: []string{"workflows"}, Timeout: time.Second}, executor)
	if r.Complete || r.Checks[0].Status != "failed" {
		t.Fatalf("zizmor error did not fail the check: %+v", r.Checks[0])
	}
}
