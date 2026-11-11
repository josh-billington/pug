//go:build integration

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/tools"
)

func TestLiveFindingExitCodes(t *testing.T) {
	if _, err := tools.LookPath("gitleaks"); err != nil {
		t.Skip("install gitleaks to verify live CLI finding exits")
	}
	repo := t.TempDir()
	fakeToken := "ghp_" + "8Qj4z6P9m1R7x3L5k2N0v4B8c6D9f1G7h3J5"
	if err := os.WriteFile(filepath.Join(repo, "config.py"), []byte("token = '"+fakeToken+"'"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		failOn string
		code   int
	}{
		{name: "high findings fail", failOn: "high", code: 1},
		{name: "explicit no finding failure", failOn: "none", code: 0},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			output := filepath.Join(t.TempDir(), "report.json")
			code := Execute(t.Context(), []string{"scan", repo, "--checks", "secrets", "--fail-on", tt.failOn, "--output", output}, &stdout, &stderr, "integration")
			var r report.Report
			if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			if code != tt.code || !r.Complete || len(r.Findings()) == 0 || strings.Contains(stdout.String(), fakeToken) {
				t.Fatalf("wrong finding behavior: exit=%d complete=%t findings=%d", code, r.Complete, len(r.Findings()))
			}
			saved, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(saved, stdout.Bytes()) {
				t.Fatalf("saved report differs from stdout: %v", err)
			}
		})
	}
}
