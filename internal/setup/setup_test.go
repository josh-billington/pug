package setup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/josh-billington/pug/internal/runner"
	"github.com/josh-billington/pug/internal/tools"
)

func TestSetupInstallsOnlyMissingToolsAndCanRetry(t *testing.T) {
	installed := map[string]bool{"gitleaks": true}
	attempts := map[string]int{}
	e := engine{
		home: t.TempDir(),
		lookup: func(name string) (string, error) {
			if installed[name] {
				return "/tools/" + name, nil
			}
			return "", exec.ErrNotFound
		},
		run: func(context.Context, runner.Invocation) runner.Result { return runner.Result{Stdout: []byte("1.0")} },
		install: func(_ context.Context, name string) (string, error) {
			attempts[name]++
			if name == "trivy" && attempts[name] == 1 {
				return "", errors.New("network offline")
			}
			installed[name] = true
			return "/tools/" + name, nil
		},
	}
	options := Options{Tools: []string{"gitleaks", "trivy", "nuclei"}, Timeout: time.Minute}
	var progress bytes.Buffer
	first := e.setup(t.Context(), options, &progress)
	if first.Ready || first.Tools[0].Status != "ready" || first.Tools[1].Status != "failed" || first.Tools[2].Status != "installed" {
		t.Fatalf("unexpected first result: %+v", first)
	}
	second := e.setup(t.Context(), options, io.Discard)
	if !second.Ready || attempts["gitleaks"] != 0 || attempts["trivy"] != 2 || attempts["nuclei"] != 1 {
		t.Fatalf("retry reinstalled working tools: %+v, attempts=%v", second, attempts)
	}
}

func TestCheckOnlyDoesNotInstallAndBrokenToolsAreNotOverwritten(t *testing.T) {
	e := engine{
		home: t.TempDir(),
		lookup: func(name string) (string, error) {
			if name == "gitleaks" {
				return "/tools/gitleaks", nil
			}
			return "", exec.ErrNotFound
		},
		run: func(context.Context, runner.Invocation) runner.Result {
			return runner.Result{Err: errors.New("broken executable"), ExitCode: 1}
		},
		install: func(context.Context, string) (string, error) {
			t.Fatal("check-only or an existing executable triggered an installation")
			return "", nil
		},
	}
	result := e.setup(t.Context(), Options{CheckOnly: true, Tools: []string{"gitleaks", "nuclei"}, Timeout: time.Minute}, io.Discard)
	if result.Ready || result.Tools[0].Status != "failed" || result.Tools[1].Status != "missing" {
		t.Fatalf("wrong readiness: %+v", result)
	}
	result = e.setup(t.Context(), Options{Tools: []string{"gitleaks"}, Timeout: time.Minute}, io.Discard)
	if result.Ready {
		t.Fatal("broken executable reported ready")
	}
}

func TestZAPSetupPullsOnlyWhenRequestedAndMissing(t *testing.T) {
	for _, check := range []bool{false, true} {
		for _, present := range []bool{false, true} {
			pulls := 0
			available := present
			e := engine{
				home:   t.TempDir(),
				lookup: func(name string) (string, error) { return name, nil },
				run: func(_ context.Context, invocation runner.Invocation) runner.Result {
					if invocation.Program == "docker" && invocation.Args[0] == "pull" {
						pulls++
						available = true
					}
					if invocation.Program == "docker" && invocation.Args[0] == "image" && !available {
						return runner.Result{Err: errors.New("no image"), ExitCode: 1}
					}
					return runner.Result{Stdout: []byte("1.0")}
				},
			}
			options := Options{CheckOnly: check, WithZAP: true, ZAPImage: tools.ZAPImage, Tools: []string{"gitleaks"}, Timeout: time.Minute}
			result := e.setup(t.Context(), options, io.Discard)
			wantPulls := 0
			if !check && !present {
				wantPulls = 1
			}
			if pulls != wantPulls || result.Ready != available {
				t.Fatalf("check=%t present=%t: pulls=%d result=%+v", check, present, pulls, result)
			}
		}
	}
}

func TestSetupCancellationAndValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	e := engine{lookup: func(string) (string, error) { return "", exec.ErrNotFound }}
	result := e.setup(ctx, Options{Tools: NativeTools, Timeout: time.Minute}, io.Discard)
	if result.Ready || len(result.Tools) != len(NativeTools) {
		t.Fatalf("cancelled setup lost coverage: %+v", result)
	}
	for _, options := range []Options{
		{},
		{Tools: []string{"unknown"}, Timeout: time.Minute},
		{Tools: []string{"trivy", "trivy"}, Timeout: time.Minute},
		{Tools: NativeTools, Timeout: -time.Second},
		{Tools: NativeTools, Timeout: time.Minute, WithZAP: true, ZAPImage: "zap:latest"},
	} {
		if err := Validate(options); err == nil {
			t.Fatalf("accepted invalid options: %+v", options)
		}
	}
}

func TestSchemathesisUsesPrivateEnvironmentWithoutProjectConfig(t *testing.T) {
	t.Setenv("UV_TOOL_BIN_DIR", "/unrelated")
	e := engine{
		home: t.TempDir(), lookup: func(string) (string, error) { return "/tools/uv", nil },
		run: func(_ context.Context, invocation runner.Invocation) runner.Result {
			args := strings.Join(invocation.Args, " ")
			if !strings.Contains(args, "--no-config") || !strings.Contains(args, "--managed-python") || !strings.Contains(args, "schemathesis==4.33.2") {
				t.Fatalf("unsafe tool install: %+v", invocation)
			}
			count := 0
			for _, value := range invocation.Env {
				if strings.HasPrefix(value, "UV_TOOL_BIN_DIR=") {
					count++
					if strings.Contains(value, "/unrelated") {
						t.Fatal("inherited conflicting tool directory")
					}
				}
			}
			if count != 1 {
				t.Fatalf("expected one bin directory, got %d", count)
			}
			return runner.Result{}
		},
	}
	if _, err := e.installTool(t.Context(), "schemathesis"); err != nil {
		t.Fatal(err)
	}
}

func TestNextStepUsesOnlyPreparedChecks(t *testing.T) {
	for _, tc := range []struct {
		tools []string
		want  string
	}{
		{NativeTools, "pug scan . --output pug-report.json"},
		{[]string{"gitleaks"}, "pug scan . --checks secrets --output pug-report.json"},
		{[]string{"trivy"}, "pug scan . --checks dependencies,infra --output pug-report.json"},
		{[]string{"nuclei"}, "pug app http://127.0.0.1:8000 --allow-active --checks exposure --templates /path/to/reviewed-templates"},
	} {
		if got := nextStep(tc.tools); got != tc.want {
			t.Fatalf("next step for %v: %q", tc.tools, got)
		}
	}
}

func TestUnsupportedLibcDoesNotDownload(t *testing.T) {
	e := engine{platform: "linux-musl/arm64"}
	if _, err := e.installTool(t.Context(), "opengrep"); err == nil || !strings.Contains(err.Error(), "glibc") {
		t.Fatalf("missing actionable libc error: %v", err)
	}
}
