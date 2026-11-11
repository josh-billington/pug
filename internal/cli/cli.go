// Package cli exposes the agent-friendly command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/runner"
	"github.com/josh-billington/pug/internal/sandbox"
	"github.com/josh-billington/pug/internal/scanner"
	"github.com/josh-billington/pug/internal/tools"
)

type exitError struct {
	code    int
	message string
}

func (e *exitError) Error() string { return e.message }

func Execute(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	root := newRoot(version)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var exit *exitError
	if errors.As(err, &exit) {
		if exit.message != "" {
			fmt.Fprintln(stderr, "pug:", exit.message)
		}
		return exit.code
	}
	fmt.Fprintln(stderr, "pug:", err)
	if ctx.Err() != nil {
		return 130
	}
	return 1
}

func usageError(format string, args ...any) error {
	return &exitError{code: 2, message: fmt.Sprintf(format, args...)}
}

func newRoot(version string) *cobra.Command {
	root := &cobra.Command{
		Use: "pug", Short: "Security evidence for coding agents", Version: version,
		SilenceUsage: true, SilenceErrors: true,
		Example: "  pug setup\n  pug scan . --output pug-report.json",
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError("%v", err) })
	root.AddCommand(scanCommand("scan", "repo", version))
	root.AddCommand(scanCommand("image", "image", version))
	root.AddCommand(scanCommand("app", "app", version))
	root.AddCommand(doctorCommand())
	root.AddCommand(setupCommand())
	root.AddCommand(diffCommand())
	root.AddCommand(sandboxCommand(version))
	return root
}

func scanCommand(name, kind, version string) *cobra.Command {
	options := scanner.Options{Kind: kind, Version: version}
	var format, output, failOn string
	var active bool
	cmd := &cobra.Command{
		Use: name + " TARGET", Short: map[string]string{
			"repo": "Scan a local working tree", "image": "Scan a digest-pinned container image",
			"app": "Actively test an application you are authorized to test",
		}[kind],
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError("%s requires exactly one target", name)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			options.Target = args[0]
			if format != "json" && format != "text" {
				return usageError("format must be json or text")
			}
			if !validThreshold(failOn) {
				return usageError("fail-on must be info, low, medium, high, critical, or none")
			}
			if kind == "app" && !active {
				return usageError("app tests send active requests; explicitly pass --allow-active for an authorized test target")
			}
			if err := scanner.Validate(&options); err != nil {
				return usageError("%v", err)
			}
			r := scanner.Scan(cmd.Context(), options, runner.Local{})
			if output != "" {
				if err := report.Save(output, r, format); err != nil {
					return err
				}
			}
			if err := report.Write(cmd.OutOrStdout(), r, format); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			if cmd.Context().Err() != nil {
				return &exitError{code: 130, message: "scan cancelled; partial report emitted"}
			}
			if !r.Complete {
				return &exitError{code: 3, message: "requested scan coverage is incomplete"}
			}
			if failOn != "none" && r.HasFindings(failOn) {
				return &exitError{code: 1, message: "findings meet the configured severity threshold"}
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&format, "format", "json", "Report format: json or text")
	flags.StringVar(&output, "output", "", "Also atomically save the report to this file (mode 0600)")
	flags.StringVar(&failOn, "fail-on", "high", "Minimum finding severity that fails the command, or none")
	flags.DurationVar(&options.Timeout, "timeout", 5*time.Minute, "Timeout per scanner, including version lookup")
	switch kind {
	case "repo":
		flags.StringSliceVar(&options.Checks, "checks", scanner.RepositoryChecks, "Checks: source,secrets,dependencies,actions,infra")
		flags.StringVar(&options.Rules, "rules", "", "Reviewed local OpenGrep rules file; default is the bundled starter pack")
	case "image":
		options.Checks = []string{"image"}
	case "app":
		flags.StringSliceVar(&options.Checks, "checks", []string{"api", "exposure"}, "Checks: api,exposure,zap")
		flags.BoolVar(&active, "allow-active", false, "Confirm authorization to send active test requests")
		flags.StringVar(&options.Schema, "schema", "", "Reviewed local OpenAPI schema for Schemathesis")
		flags.StringVar(&options.Templates, "templates", "", "Reviewed local HTTP Nuclei templates")
		flags.StringVar(&options.ZAPImage, "zap-image", tools.ZAPImage, "Locally installed ZAP Docker image pinned by digest")
	}
	return cmd
}

func validThreshold(value string) bool {
	switch value {
	case "info", "low", "medium", "high", "critical", "none":
		return true
	default:
		return false
	}
}

func doctorCommand() *cobra.Command {
	return &cobra.Command{
		Use: "doctor", Short: "List scanner availability without running scans", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			type dependency struct {
				Tool      string `json:"tool"`
				Path      string `json:"path,omitempty"`
				Available bool   `json:"available"`
			}
			toolNames := map[string]bool{"git": true}
			for _, name := range scanner.Tools {
				toolNames[name] = true
			}
			names := make([]string, 0, len(toolNames))
			for name := range toolNames {
				names = append(names, name)
			}
			sort.Strings(names)
			items := []dependency{}
			for _, name := range names {
				path, err := tools.LookPath(name)
				items = append(items, dependency{Tool: name, Path: path, Available: err == nil})
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(items)
		},
	}
}

func diffCommand() *cobra.Command {
	return &cobra.Command{
		Use: "diff BEFORE.json AFTER.json", Short: "Compare findings without treating failed scans as fixes", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			before, err := report.Load(args[0])
			if err != nil {
				return err
			}
			after, err := report.Load(args[1])
			if err != nil {
				return err
			}
			comparison, err := report.Compare(before, after)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(comparison)
		},
	}
}

func sandboxCommand(version string) *cobra.Command {
	var options sandbox.Options
	var format, output string
	cmd := &cobra.Command{
		Use: "sandbox [flags] -- COMMAND [ARG...]", Short: "Run an agent and optional app in a disposable offline container",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 0 {
				return usageError("sandbox command must follow --")
			}
			if format != "json" && format != "text" {
				return usageError("format must be json or text")
			}
			options.Command = args
			if err := sandbox.Validate(&options); err != nil {
				return usageError("%v", err)
			}
			r, err := sandbox.Run(cmd.Context(), options, runner.Local{}, version)
			if err != nil {
				return err
			}
			if output != "" {
				if err := report.Save(output, r, format); err != nil {
					return err
				}
			}
			if err := report.Write(cmd.OutOrStdout(), r, format); err != nil {
				return err
			}
			if cmd.Context().Err() != nil {
				return &exitError{code: 130, message: "sandbox cancelled"}
			}
			if !r.Complete {
				return &exitError{code: 3, message: "sandbox run incomplete"}
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&options.Repo, "repo", ".", "Clean Git checkout to snapshot (tracked regular files only)")
	flags.StringVar(&options.Image, "image", "", "Locally installed image pinned as name@sha256:digest")
	flags.StringVar(&options.AppJSON, "app-command", "", "Optional app argv as a JSON array, started beside the agent")
	flags.DurationVar(&options.Timeout, "timeout", 2*time.Minute, "Maximum container runtime")
	flags.StringVar(&format, "format", "json", "Report format: json or text")
	flags.StringVar(&output, "output", "", "Also atomically save the sandbox evidence report")
	return cmd
}
