package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josh-billington/pug/internal/setup"
)

func TestUsageErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
	}{
		{name: "invalid setup tool", args: []string{"setup", "--tools", "unknown"}},
		{name: "invalid setup format", args: []string{"setup", "--format", "yaml"}},
		{name: "invalid setup timeout", args: []string{"setup", "--timeout", "0s"}},
		{name: "multiple targets", args: []string{"scan", ".", "other"}},
		{name: "conflicting setup selectors", args: []string{"setup", "--repo", "--tools", "opengrep"}},
		{name: "unknown flag", args: []string{"scan", ".", "--made-up"}},
		{name: "active opt-in", args: []string{"app", "http://localhost:8000"}},
		{name: "port scan opt-in", args: []string{"net", "127.0.0.1", "--ports", "22", "--expect", "22"}},
		{name: "port scan hostname", args: []string{"net", "localhost", "--ports", "22", "--expect", "22", "--allow-active"}},
		{name: "mutable image", args: []string{"image", "alpine:latest"}},
		{name: "invalid format", args: []string{"scan", ".", "--format", "yaml"}},
		{name: "sarif for an image", args: []string{"image", "alpine@sha256:" + strings.Repeat("a", 64), "--format", "sarif"}},
		{name: "sarif for a sandbox", args: []string{"sandbox", "--format", "sarif", "--", "echo"}},
		{name: "invalid timeout", args: []string{"scan", ".", "--timeout", "-1s"}},
		{name: "invalid threshold", args: []string{"scan", ".", "--fail-on", "anything"}},
		{name: "sandbox separator", args: []string{"sandbox", "echo"}},
		{name: "option-like rule pack", args: []string{"scan", ".", "--rules", "-x"}},
		{name: "invalid profile", args: []string{"scan", ".", "--rules", "amplify:.."}},
		{name: "missing rules file", args: []string{"scan", ".", "--rules", "starter,missing.yml"}},
		{name: "rules install without packs", args: []string{"rules", "install"}},
		{name: "rules install unknown pack", args: []string{"rules", "install", "amplify", "made-up"}},
		{name: "rules list with arguments", args: []string{"rules", "list", "extra"}},
		{name: "doctor with arguments", args: []string{"doctor", "extra"}},
		{name: "diff with one report", args: []string{"diff", "before.json"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := Execute(t.Context(), tt.args, &stdout, &stderr, "test")
			if code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestScanDefaultsToCurrentDirectoryWithShortFlags(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("PUG_HOME", t.TempDir())
	root := t.TempDir()
	t.Chdir(root)
	output := filepath.Join(root, "report.json")
	var stdout, stderr bytes.Buffer
	code := Execute(t.Context(), []string{"scan", "-c", "secrets", "-o", output, "-f", "json"}, &stdout, &stderr, "test")
	var result struct {
		Target string                  `json:"target"`
		Checks []struct{ Name string } `json:"checks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || code != 3 || len(result.Checks) != 1 || result.Checks[0].Name != "secrets" {
		t.Fatalf("scan did not select secrets: exit=%d, stdout=%s, stderr=%s", code, &stdout, &stderr)
	}
	resolved, err := filepath.EvalSymlinks(result.Target)
	canonical, rootErr := filepath.EvalSymlinks(root)
	if err != nil || rootErr != nil || resolved != canonical {
		t.Fatalf("target = %q; want %q", result.Target, root)
	}
	if saved, err := os.ReadFile(output); err != nil || !bytes.Equal(saved, stdout.Bytes()) {
		t.Fatalf("output not saved: %v", err)
	}
}

func TestScanWritesSARIFWithoutRunsForChecksThatDidNotComplete(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("PUG_HOME", t.TempDir())
	root := t.TempDir()
	output := filepath.Join(root, "pug.sarif")
	var stdout, stderr bytes.Buffer
	code := Execute(t.Context(), []string{"scan", root, "-c", "secrets", "-f", "sarif", "-o", output}, &stdout, &stderr, "test")
	var log struct {
		Version string            `json:"version"`
		Runs    []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &log); err != nil || code != 3 || log.Version != "2.1.0" || log.Runs == nil || len(log.Runs) != 0 {
		t.Fatalf("exit=%d, stdout=%s, stderr=%s", code, &stdout, &stderr)
	}
	if saved, err := os.ReadFile(output); err != nil || !bytes.Equal(saved, stdout.Bytes()) {
		t.Fatalf("SARIF not saved: %v", err)
	}
}

func TestSetupRepoSelectsRepositoryTools(t *testing.T) {
	t.Setenv("PATH", "")
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	var stdout, stderr bytes.Buffer
	code := Execute(t.Context(), []string{"setup", "--repo", "--check", "--format", "json"}, &stdout, &stderr, "test")
	var result setup.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || code != 3 || result.Ready {
		t.Fatalf("setup --repo --check: exit=%d, stdout=%s, stderr=%s", code, &stdout, &stderr)
	}
	if len(result.Tools) != len(setup.RepositoryTools) {
		t.Fatalf("selected tools: %+v", result.Tools)
	}
	for index, tool := range result.Tools {
		if tool.Name != setup.RepositoryTools[index] || tool.Status != "missing" {
			t.Fatalf("unexpected tool %+v", tool)
		}
	}
}

func TestHelpAndDoctor(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"--help"}, &stdout, &stderr, "test"); code != 0 || !strings.Contains(stdout.String(), "sandbox") {
		t.Fatalf("help failed: %d, %s", code, stderr.String())
	}
	stdout.Reset()
	if code := Execute(t.Context(), []string{"doctor"}, &stdout, &stderr, "test"); code != 0 || !json.Valid(stdout.Bytes()) {
		t.Fatalf("doctor output invalid: %d, %s", code, stdout.String())
	}
}

func TestIncompleteAndCancelledScansEmitJSON(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("PUG_HOME", t.TempDir())
	for _, cancelled := range []bool{false, true} {
		name := "unavailable"
		if cancelled {
			name = "cancelled"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := 3
			if cancelled {
				cancel()
				want = 130
			}
			var stdout, stderr bytes.Buffer
			code := Execute(ctx, []string{"scan", t.TempDir(), "--checks", "secrets", "--fail-on", "none"}, &stdout, &stderr, "test")
			if code != want || !json.Valid(stdout.Bytes()) || !strings.Contains(stdout.String(), `"complete": false`) {
				t.Fatalf("partial report lost: exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRulesListAndUninstalledPackScan(t *testing.T) {
	t.Setenv("PATH", "")
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"rules", "list"}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("rules list failed: %d %s", code, stderr.String())
	}
	var packs []struct {
		Name      string   `json:"name"`
		Commit    string   `json:"commit"`
		URL       string   `json:"url"`
		Installed bool     `json:"installed"`
		Path      string   `json:"path"`
		Profiles  []string `json:"profiles"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &packs); err != nil {
		t.Fatalf("rules list output: %s, %v", stdout.String(), err)
	}
	wantURLs := map[string]string{
		"aikido":   "https://github.com/AikidoSec/opengrep-rules.git",
		"amplify":  "https://github.com/amplify-security/opengrep-rules.git",
		"opengrep": "https://github.com/opengrep/opengrep-rules.git",
	}
	gotURLs := map[string]string{}
	for _, p := range packs {
		gotURLs[p.Name] = p.URL
		if p.Installed || p.Commit != "" || p.Path != filepath.Join(home, "rules", p.Name) || p.Profiles == nil || len(p.Profiles) != 0 {
			t.Fatalf("unexpected pack status: %+v", p)
		}
	}
	if len(packs) != len(wantURLs) || !maps.Equal(gotURLs, wantURLs) {
		t.Fatalf("aliases = %v, want %v", gotURLs, wantURLs)
	}
	stdout.Reset()
	code := Execute(t.Context(), []string{"scan", t.TempDir(), "--checks", "source", "--rules", "notinstalled", "--fail-on", "none"}, &stdout, &stderr, "test")
	if code != 3 || !strings.Contains(stdout.String(), "run: pug rules install notinstalled") {
		t.Fatalf("scan with an uninstalled pack: exit=%d stdout=%s", code, stdout.String())
	}
	if _, err := os.Stat(filepath.Join(home, "rules")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scan wrote to the rules directory: %v", err)
	}
}

func TestScanRejectsProfileOnRulesFile(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("PUG_HOME", t.TempDir())
	file := filepath.Join(t.TempDir(), "team.yml")
	if err := os.WriteFile(file, []byte("rules:\n  - id: team-rule\n    languages: [python]\n    severity: ERROR\n    message: m\n    pattern: f()\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Execute(t.Context(), []string{"scan", t.TempDir(), "--checks", "source", "--rules", file + ":audit"}, &stdout, &stderr, "test")
	if code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("profile on a rules file: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestSetupCheckProducesJSONWithoutWriting(t *testing.T) {
	t.Setenv("PATH", "")
	home := filepath.Join(t.TempDir(), "unused")
	t.Setenv("PUG_HOME", home)
	var stdout, stderr bytes.Buffer
	code := Execute(t.Context(), []string{"setup", "--check", "--format", "json"}, &stdout, &stderr, "test")
	var result struct {
		Ready bool `json:"ready"`
		Tools []struct {
			Status string `json:"status"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || code != 3 || result.Ready || len(result.Tools) != len(setup.NativeTools) {
		t.Fatalf("bad setup result: code=%d output=%s err=%v", code, stdout.String(), err)
	}
	for _, tool := range result.Tools {
		if tool.Status != "missing" {
			t.Fatalf("unexpected tool status %s", tool.Status)
		}
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("check-only created its home: %v", err)
	}
}

func TestRulesListDiscoversLocalPacks(t *testing.T) {
	t.Setenv("PATH", "")
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	for _, name := range []string{"team/configs", ".tmp-running", ".hidden"} {
		if err := os.MkdirAll(filepath.Join(home, "rules", name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "rules", "team", "configs", "audit.list"), []byte("python/eval.yaml:eval\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"rules", "list"}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("list: %d %s", code, stderr.String())
	}
	var statuses []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &statuses); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, status := range statuses {
		name, _ := status["name"].(string)
		names = append(names, name)
	}
	if !slices.Equal(names, []string{"aikido", "amplify", "opengrep", "team"}) {
		t.Fatalf("listed packs = %v, want aliases plus team without workspaces", names)
	}
	team := statuses[3]
	if team["installed"] != true || team["path"] != filepath.Join(home, "rules", "team") {
		t.Fatalf("local pack status: %v", team)
	}
	if commit, _ := team["commit"].(string); commit != "" {
		t.Fatalf("non-git pack reports a commit: %v", team)
	}
	if url, _ := team["url"].(string); url != "" {
		t.Fatalf("local pack reports a URL: %v", team)
	}
	if profiles, ok := team["profiles"].([]any); !ok || len(profiles) != 1 || profiles[0] != "audit" {
		t.Fatalf("local pack profiles: %v", team["profiles"])
	}
}

func TestRulesInstallReportsMissingGit(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("PUG_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	if code := Execute(t.Context(), []string{"rules", "install", "amplify"}, &stdout, &stderr, "test"); code != 1 || !strings.Contains(stderr.String(), "pug doctor") {
		t.Fatalf("missing git: %d %s", code, stderr.String())
	}
}
