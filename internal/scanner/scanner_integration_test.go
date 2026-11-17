//go:build integration

package scanner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/rules"
	"github.com/josh-billington/pug/internal/runner"
	"github.com/josh-billington/pug/internal/tools"
)

func requireTool(t *testing.T, tool string) {
	t.Helper()
	if _, err := tools.LookPath(tool); err != nil {
		t.Skipf("install %s to run this integration test", tool)
	}
}

func fixtureFile(t *testing.T, root, name, data string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRealRepositoryScanners(t *testing.T) {
	cases := []struct {
		name string
		tool string
	}{
		{name: "secrets", tool: "gitleaks"},
		{name: "actions", tool: "actionlint"},
		{name: "source", tool: "opengrep"},
		{name: "infra", tool: "trivy"},
		{name: "dependencies", tool: "trivy"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			requireTool(t, tt.tool)
			repo := t.TempDir()
			fakeToken := "ghp_" + "8Qj4z6P9m1R7x3L5k2N0v4B8c6D9f1G7h3J5"
			fixtureFile(t, repo, "credentials.py", "github_token = '"+fakeToken+"'\n")
			fixtureFile(t, repo, "unsafe.js", "function unsafe(input) { return eval(input); }\n")
			fixtureFile(t, repo, ".github/workflows/test.yml", "name: test\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '${{ secrets.DOES_NOT_EXIST.foo.bar }}'\n      - uses: actions/checkout@v4\n      - run: echo '${{ made_up.context }}'\n")
			fixtureFile(t, repo, "Dockerfile", "FROM alpine:3.18\nUSER root\nCMD [\"sh\"]\n")
			fixtureFile(t, repo, "package.json", `{"name":"pug-vulnerable-fixture","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}`)
			fixtureFile(t, repo, "package-lock.json", `{"name":"pug-vulnerable-fixture","version":"1.0.0","lockfileVersion":2,"packages":{"":{"dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}},"dependencies":{"lodash":{"version":"4.17.20"}}}`)
			options := Options{Kind: "repo", Target: repo, Checks: []string{tt.name}, Timeout: 3 * time.Minute, Version: "integration"}
			if err := Validate(&options); err != nil {
				t.Fatal(err)
			}
			r := Scan(t.Context(), options, runner.Local{})
			if !r.Complete || len(r.Findings()) == 0 {
				data, _ := json.MarshalIndent(r, "", "  ")
				t.Fatalf("real scanner did not find vulnerable fixture:\n%s", data)
			}
			data, err := json.Marshal(r)
			if err != nil || strings.Contains(string(data), fakeToken) {
				t.Fatal("report exposed the fake token")
			}
			t.Logf("%s: %d findings, tool %s", tt.name, len(r.Findings()), r.Checks[0].Version)
			if tt.name == "secrets" {
				if err := os.Remove(filepath.Join(repo, "credentials.py")); err != nil {
					t.Fatal(err)
				}
				after := Scan(t.Context(), options, runner.Local{})
				diff, err := report.Compare(r, after)
				if err != nil || !after.Complete || len(diff.Absent) == 0 || len(diff.New) != 0 {
					t.Fatalf("real retest did not clear fixture evidence: %+v, %v", diff, err)
				}
			}
		})
	}
}

func TestRealOpenGrepPartialParseCompletesWithoutStrict(t *testing.T) {
	requireTool(t, "opengrep")
	const evalRule = "  - id: ruby-eval\n    languages: [ruby]\n    severity: ERROR\n    message: eval\n    pattern: eval(...)\n"
	cases := []struct {
		name   string
		rules  string
		status string
		reason string
	}{
		{name: "malformed target", rules: "rules:\n" + evalRule, status: "completed", reason: "partial"},
		{name: "invalid rule", rules: "rules:\n" + evalRule + "  - id: broken\n    languages: [python]\n    severity: ERROR\n    message: bad\n    pattern: \"def (((\"\n", status: "failed"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			fixtureFile(t, repo, "good.rb", "eval(params[:x])\n")
			fixtureFile(t, repo, "bad.rb", "def broken(\n  eval(x\nclass << <<< end end end )))\n")
			rulesFile := fixtureFile(t, t.TempDir(), "rules.yml", tt.rules)
			options := Options{Kind: "repo", Target: repo, Checks: []string{"source"}, Rules: []rules.Spec{{Kind: rules.FileSpec, Path: rulesFile}}, Timeout: 3 * time.Minute, Version: "integration"}
			if err := Validate(&options); err != nil {
				t.Fatal(err)
			}
			check := Scan(t.Context(), options, runner.Local{}).Checks[0]
			if check.Status != tt.status || !strings.Contains(check.Reason, tt.reason) {
				t.Fatalf("status=%s reason=%q", check.Status, check.Reason)
			}
			if tt.status == "completed" && (len(check.Findings) != 1 || check.Findings[0].Severity != "high") {
				t.Fatalf("finding in the parsable file lost or misrated: %+v", check.Findings)
			}
		})
	}
}

type archiveTransport []byte

func (a archiveTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(a)), Header: http.Header{}}, nil
}

func packArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "fixture-rules-0123/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestRealRulePackScan(t *testing.T) {
	requireTool(t, "opengrep")
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	archive := packArchive(t, map[string]string{
		"LICENSE": "MIT",
		"python/lang/eval.yaml": "rules:\n" +
			"  - id: eval\n    languages: [python]\n    severity: ERROR\n    message: eval of input\n    pattern: eval(...)\n" +
			"  - id: exec-used\n    languages: [python]\n    severity: WARNING\n    message: exec of input\n    pattern: exec(...)\n",
		// Rule-shaped fixture with no message: OpenGrep rejects the whole config if it is installed.
		"python/lang/eval.test.yaml": "rules:\n  - id: eval\n    languages: [python]\n    pattern: eval(...)\n",
		"configs/default.list":       "python/lang/eval.yml:eval\npython/lang/eval.yaml:exec-used\npython/lang/gone.yaml:gone\n",
	})
	sum := sha256.Sum256(archive)
	pack := rules.Pack{
		Name: "fixture", Repo: "example/rules", Commit: strings.Repeat("0", 40), SHA256: hex.EncodeToString(sum[:]),
		License: "MIT", RuleDirs: []string{"python"}, ProfilesDir: "configs", DefaultProfile: "default",
	}
	if _, _, err := rules.Install(t.Context(), &http.Client{Transport: archiveTransport(archive)}, home, pack); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	fixtureFile(t, repo, "app.py", "def handler(x, y):\n    eval(x)\n    exec(y)\n")
	fixtureFile(t, repo, "broken.py", "def broken(:\n    eval(\n")
	scan := func() report.Report {
		options := Options{Kind: "repo", Target: repo, Checks: []string{"source"}, Timeout: 3 * time.Minute, Version: "integration",
			Rules: []rules.Spec{{Kind: rules.PackSpec, Pack: pack}}}
		if err := Validate(&options); err != nil {
			t.Fatal(err)
		}
		return Scan(t.Context(), options, runner.Local{})
	}
	before := scan()
	check := before.Checks[0]
	got := map[string]string{}
	for _, finding := range check.Findings {
		got[finding.Rule] = finding.Severity
	}
	want := map[string]string{"fixture.python.lang.eval": "high", "fixture.python.lang.eval.exec-used": "medium"}
	if check.Status != "completed" || fmt.Sprint(got) != fmt.Sprint(want) {
		data, _ := json.MarshalIndent(check, "", "  ")
		t.Fatalf("pack scan findings = %v, want %v:\n%s", got, want, data)
	}
	if !strings.Contains(check.Reason, "partial") || !strings.Contains(check.Reason, "skipped 1 profile entries") || check.Rules == nil || check.Rules.Packs["fixture"] != pack.Commit {
		t.Fatalf("reason or provenance incomplete: %q %+v", check.Reason, check.Rules)
	}
	diff, err := report.Compare(before, scan())
	if err != nil || len(diff.New) != 0 || len(diff.Absent) != 0 || len(diff.Unverified) != 0 || len(diff.Persistent) != 2 {
		t.Fatalf("rescan with the same pack was not stable: %+v, %v", diff, err)
	}
}

func TestRealApplicationScanners(t *testing.T) {
	for _, name := range []string{"api", "exposure"} {
		t.Run(name, func(t *testing.T) {
			requireTool(t, Tools[name])
			var requests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if name == "api" {
					w.WriteHeader(http.StatusInternalServerError)
				}
				fmt.Fprint(w, `{"pug_fixture":"exposed"}`)
			}))
			defer server.Close()
			dir := t.TempDir()
			schema := fixtureFile(t, dir, "openapi.json", `{"openapi":"3.0.3","info":{"title":"Pug fixture","version":"1"},"paths":{"/items":{"get":{"responses":{"200":{"description":"OK","content":{"application/json":{"schema":{"type":"object"}}}}}}}}}`)
			template := fixtureFile(t, dir, "exposed.yaml", "id: pug-fixture\ninfo:\n  name: Pug test exposure\n  author: pug\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/items'\n    matchers:\n      - type: word\n        words:\n          - 'pug_fixture'\n")
			options := Options{
				Kind: "app", Target: server.URL, Checks: []string{name}, Timeout: 90 * time.Second,
				Schema: schema, Templates: template, Version: "integration",
			}
			if err := Validate(&options); err != nil {
				t.Fatal(err)
			}
			r := Scan(t.Context(), options, runner.Local{})
			if !r.Complete || len(r.Findings()) == 0 || requests.Load() == 0 {
				data, _ := json.MarshalIndent(r, "", "  ")
				t.Fatalf("application scan did not produce live findings (requests=%d):\n%s", requests.Load(), data)
			}
			t.Logf("%s: %d findings from %d live requests", name, len(r.Findings()), requests.Load())
		})
	}
}

// TestRealZAP requires Docker Desktop so the container can reach the host fixture.
func TestRealZAP(t *testing.T) {
	image := os.Getenv("PUG_TEST_ZAP_IMAGE")
	if image == "" {
		t.Skip("set PUG_TEST_ZAP_IMAGE to a locally installed digest-pinned ZAP image")
	}
	requireTool(t, "docker")
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><body>Not found</body></html>")
			return
		}
		fmt.Fprint(w, "<html><head><title>Pug ZAP fixture</title></head><body>Local test fixture</body></html>")
	}))
	server.Listener.Close()
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()
	options := Options{
		Kind: "app", Target: fmt.Sprintf("http://host.docker.internal:%d", listener.Addr().(*net.TCPAddr).Port),
		Checks: []string{"zap"}, ZAPImage: image, Timeout: 10 * time.Minute, Version: "integration",
	}
	if err := Validate(&options); err != nil {
		t.Fatal(err)
	}
	r := Scan(t.Context(), options, runner.Local{})
	if !r.Complete || len(r.Findings()) == 0 || requests.Load() == 0 || r.Checks[0].EvidenceSHA256 == "" {
		data, _ := json.MarshalIndent(r, "", "  ")
		t.Fatalf("ZAP scan did not produce live findings (requests=%d):\n%s", requests.Load(), data)
	}
	for _, finding := range r.Findings() {
		if finding.Tool != "zap" || finding.Fingerprint == "" {
			t.Fatalf("invalid normalized ZAP finding: %+v", finding)
		}
	}
	t.Logf("zap: %d findings from %d live requests; scanner exit %d; evidence %s", len(r.Findings()), requests.Load(), r.Checks[0].ExitCode, r.Checks[0].EvidenceSHA256)
}

// TestZAPWorkspaceCleanup has the ZAP image's own user create a locked
// directory in the bind mount, which the host cannot remove (on Linux it is
// owned by uid 1000; on any host its 0500 mode blocks unlinking), then checks
// the container cleanup fallback removes it without touching the private parent.
func TestZAPWorkspaceCleanup(t *testing.T) {
	image := os.Getenv("PUG_TEST_ZAP_IMAGE")
	if image == "" {
		t.Skip("set PUG_TEST_ZAP_IMAGE to a locally installed digest-pinned ZAP image")
	}
	requireTool(t, "docker")
	temp, err := os.MkdirTemp("", "pug-*")
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(temp, "zap")
	if err := os.Mkdir(work, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(work, 0o777); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	seed := runner.Local{}.Run(ctx, runner.Invocation{Program: "docker", Args: []string{
		"run", "--rm", "--pull=never", "--network=none", "--mount", "type=bind,src=" + work + ",dst=/zap/wrk",
		"--entrypoint", "/bin/sh", image, "-c",
		"mkdir -p /zap/wrk/session/nested && echo x > /zap/wrk/session/nested/state && chmod 0500 /zap/wrk/session/nested /zap/wrk/session",
	}})
	if seed.Err != nil || seed.ExitCode != 0 {
		t.Fatalf("seed container failed (exit %d): %s", seed.ExitCode, seed.Stderr)
	}
	if err := os.RemoveAll(temp); err == nil {
		// Docker Desktop's file sharing maps container-written files to the host
		// user and keeps their modes virtual, so the host can always remove them.
		t.Skip("host removed the container-created directory; run against a native Linux Docker daemon as a non-root uid other than 1000")
	}
	info, err := os.Stat(temp)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private parent should remain 0700, got %v %v", info.Mode(), err)
	}
	if err := cleanupWorkspace(ctx, runner.Local{}, temp, plan{mount: work, image: image}); err != nil {
		t.Fatalf("cleanup fallback failed: %v", err)
	}
	if _, err := os.Lstat(temp); !os.IsNotExist(err) {
		t.Fatalf("workspace still present after fallback: %v", err)
	}
}
