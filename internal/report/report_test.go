package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceRoundTrip(t *testing.T) {
	t.Parallel()
	f := Finding{Check: "secrets", Tool: "gitleaks", Rule: "token", Severity: "high", Location: "config", Line: 2}
	f.Identify()
	r := Report{SchemaVersion: "1", Target: "/repo", Checks: []Check{{Name: "secrets", Status: "completed", Findings: []Finding{f}}}}
	r.Finalize(map[string]bool{"secrets": true}, []string{"secrets", "source"})
	if !r.Complete || len(r.NotTested) != 1 || !r.HasFindings("high") || r.HasFindings("critical") {
		t.Fatalf("incorrect report: %+v", r)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := Save(path, r, "json"); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || len(got.Findings()) != 1 || got.Findings()[0].Fingerprint != f.Fingerprint {
		t.Fatalf("round trip failed: %+v, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report not private: %v, %v", info, err)
	}
}

func TestSaveDoesNotFollowSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "report")
	if err := os.Symlink(victim, path); err != nil {
		t.Skip(err)
	}
	if err := Save(path, Report{SchemaVersion: "1"}, "json"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(victim)
	if err != nil || string(data) != "keep" {
		t.Fatalf("symlink target overwritten: %q, %v", data, err)
	}
}

func TestLoadRejectsInvalidEvidence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data string
	}{
		{name: "unknown schema", data: `{"schema_version":"99","target":"/repo","checks":[]}`},
		{name: "missing target", data: `{"schema_version":"1","checks":[]}`},
		{name: "trailing document", data: `{"schema_version":"1","target":"/repo","checks":[]} {}`},
		{name: "invalid status", data: `{"schema_version":"1","target":"/repo","checks":[{"name":"source","status":"clean"}]}`},
		{name: "forged fingerprint", data: `{"schema_version":"1","target":"/repo","checks":[{"name":"source","status":"completed","findings":[{"check":"source","fingerprint":"forged"}]}]}`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("invalid comparison evidence accepted")
			}
		})
	}
}

func TestTextOutputStripsTerminalControls(t *testing.T) {
	t.Parallel()
	r := Report{Target: "/repo\x1b[2J", Checks: []Check{{Name: "source", Status: "failed", Reason: "bad\x1b]0;title\x07\rtool"}}}
	var out strings.Builder
	if err := Write(&out, r, "text"); err != nil {
		t.Fatal(err)
	}
	if text := out.String(); strings.ContainsAny(text, "\x1b\r\x07") || !strings.Contains(text, "bad tool") || !strings.Contains(text, "\n") {
		t.Fatalf("unsafe text output: %q", text)
	}
}
