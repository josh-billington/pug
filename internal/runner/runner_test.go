package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if len(os.Args) < 2 || !strings.HasPrefix(os.Args[len(os.Args)-1], "pug-helper-") {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "pug-helper-output":
		fmt.Print("evidence")
		os.Exit(7)
	case "pug-helper-large":
		fmt.Print(strings.Repeat("x", MaxOutput+100))
		os.Exit(0)
	case "pug-helper-wait":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func TestLocalExecution(t *testing.T) {
	t.Parallel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	result := (Local{}).Run(t.Context(), Invocation{Program: executable, Args: []string{"-test.run=^TestHelperProcess$", "--", "pug-helper-output"}})
	if result.ExitCode != 7 || string(result.Stdout) != "evidence" {
		t.Fatalf("lost process evidence: %+v", result)
	}
	result = (Local{}).Run(t.Context(), Invocation{Program: executable, Args: []string{"-test.run=^TestHelperProcess$", "--", "pug-helper-large"}})
	if !result.Truncated || len(result.Stdout) != MaxOutput {
		t.Fatalf("output not bounded: %d bytes, truncated=%t", len(result.Stdout), result.Truncated)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	result = (Local{}).Run(ctx, Invocation{Program: executable, Args: []string{"-test.run=^TestHelperProcess$", "--", "pug-helper-wait"}})
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("cancellation not propagated: %v", result.Err)
	}
}
