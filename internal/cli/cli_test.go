package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		{name: "missing target", args: []string{"scan"}},
		{name: "unknown flag", args: []string{"scan", ".", "--made-up"}},
		{name: "active opt-in", args: []string{"app", "http://localhost:8000"}},
		{name: "mutable image", args: []string{"image", "alpine:latest"}},
		{name: "invalid format", args: []string{"scan", ".", "--format", "yaml"}},
		{name: "invalid timeout", args: []string{"scan", ".", "--timeout", "-1s"}},
		{name: "invalid threshold", args: []string{"scan", ".", "--fail-on", "anything"}},
		{name: "sandbox separator", args: []string{"sandbox", "echo"}},
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
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || code != 3 || result.Ready || len(result.Tools) != 6 {
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
