package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/josh-billington/pug/internal/rules"
	"github.com/josh-billington/pug/internal/runner"
	"github.com/josh-billington/pug/internal/tools"
)

func rulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "rules", Short: "List and install OpenGrep rule repositories",
		Long: "Install upstream OpenGrep rule repositories with git.\nPug fetches rules only when you run pug rules install; source scans use local rules.\nSelect installed packs with pug scan --rules.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(rulesListCommand(), rulesInstallCommand())
	return cmd
}

type packStatus struct {
	Name      string   `json:"name"`
	URL       string   `json:"url,omitempty"`
	Installed bool     `json:"installed"`
	Path      string   `json:"path"`
	Commit    string   `json:"commit,omitempty"`
	Profiles  []string `json:"profiles"`
}

func rulesListCommand() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List installed packs and built-in aliases as JSON", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := tools.Home()
			if err != nil {
				return err
			}
			names := rules.Names()
			entries, err := os.ReadDir(filepath.Join(home, "rules"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("list rule packs: %w", err)
			}
			for _, entry := range entries {
				if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && !slices.Contains(names, entry.Name()) {
					names = append(names, entry.Name())
				}
			}
			slices.Sort(names)
			statuses := make([]packStatus, 0, len(names))
			for _, name := range names {
				status := packStatus{Name: name, URL: rules.Aliases[name], Path: rules.Dir(home, name), Profiles: []string{}}
				info, err := os.Stat(status.Path)
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("inspect rule pack: %w", err)
				}
				status.Installed = err == nil && info.IsDir()
				if status.Installed {
					status.Commit, err = rules.Commit(cmd.Context(), runner.Local{}, status.Path)
					if err != nil {
						return err
					}
					status.Profiles, err = rules.Profiles(status.Path)
					if err != nil {
						return err
					}
				}
				statuses = append(statuses, status)
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(statuses)
		},
	}
}

func rulesInstallCommand() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use: "install NAME|URL[@COMMIT]...", Short: "Clone or update upstream rule repositories",
		Example: "  pug rules install amplify\n  pug rules install github.com/trailofbits/semgrep-rules\n  pug scan . --checks source --rules amplify:security-audit",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if timeout <= 0 {
				return usageError("timeout must be positive")
			}
			specs := make([]rules.InstallSpec, 0, len(args))
			for _, value := range args {
				spec, err := rules.ParseInstallSpec(value)
				if err != nil {
					return usageError("%v", err)
				}
				specs = append(specs, spec)
			}
			home, err := tools.Home()
			if err != nil {
				return usageError("%v", err)
			}
			failed := false
			for _, spec := range specs {
				ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
				commit, err := rules.Install(ctx, runner.Local{}, home, spec)
				cancel()
				if err != nil {
					failed = true
					fmt.Fprintf(cmd.ErrOrStderr(), "pug: %s: %v\n", spec.Name, err)
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s in %s\n", spec.Name, commit[:min(12, len(commit))], rules.Dir(home, spec.Name))
			}
			if cmd.Context().Err() != nil {
				return &exitError{code: 130, message: "rule pack installation cancelled; rerun pug rules install to continue"}
			}
			if failed {
				return &exitError{code: 1, message: "rule pack installation failed"}
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Timeout per repository install")
	return cmd
}
