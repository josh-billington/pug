package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/josh-billington/pug/internal/setup"
	"github.com/josh-billington/pug/internal/tools"
)

func setupCommand() *cobra.Command {
	var options setup.Options
	var format string
	cmd := &cobra.Command{
		Use: "setup", Short: "Check scanners and install missing tools",
		Long: "Check installed scanners and install missing ones into ~/.local/share/pug.\nSetup uses pinned releases. It does not use sudo or change shell profiles.\nSet PUG_HOME to an absolute path to use another directory.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != "text" && format != "json" {
				return usageError("format must be text or json")
			}
			if err := setup.Validate(options); err != nil {
				return usageError("%v", err)
			}
			if format == "text" {
				fmt.Fprintln(cmd.OutOrStdout(), "Pug setup")
				fmt.Fprintln(cmd.OutOrStdout())
				if options.CheckOnly {
					fmt.Fprintln(cmd.OutOrStdout(), "Checking tools without installing anything.")
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "Checking tools and installing missing scanners.")
				}
			}
			result, err := setup.Run(cmd.Context(), options, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if format == "json" {
				err = json.NewEncoder(cmd.OutOrStdout()).Encode(result)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "\nTools directory: %s/bin\n", result.Home)
				fmt.Fprintf(cmd.OutOrStdout(), "Docker: %s", result.Docker.Status)
				if result.Docker.Detail != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "\n  %s", result.Docker.Detail)
				}
				fmt.Fprintln(cmd.OutOrStdout())
				if result.Git.Status != "ready" {
					fmt.Fprintln(cmd.OutOrStdout(), result.Git.Detail)
				}
				if result.ZAP != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "ZAP: %s\n", result.ZAP.Status)
					if result.ZAP.Detail != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", result.ZAP.Detail)
					}
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "For ZAP, run pug setup --with-zap. Docker must be running.")
				}
				if result.Ready {
					fmt.Fprintln(cmd.OutOrStdout(), "\nSelected scanners are ready.")
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "\nNext: %s\n", result.NextStep)
			}
			if err != nil {
				return err
			}
			if cmd.Context().Err() != nil {
				return &exitError{code: 130, message: "setup cancelled. Rerun pug setup to continue"}
			}
			if !result.Ready {
				return &exitError{code: 3, message: "setup is incomplete"}
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&options.CheckOnly, "check", false, "Check tools without downloading or installing")
	flags.StringSliceVar(&options.Tools, "tools", setup.NativeTools, "Scanners to check and install if missing")
	flags.BoolVar(&options.WithZAP, "with-zap", false, "Also pull the pinned ZAP image. Requires Docker")
	flags.StringVar(&options.ZAPImage, "zap-image", tools.ZAPImage, "Digest-pinned ZAP image to pull if missing")
	flags.DurationVar(&options.Timeout, "timeout", 10*time.Minute, "Timeout per tool installation")
	flags.StringVar(&format, "format", "text", "Output format: text or json. Progress goes to stderr")
	return cmd
}
