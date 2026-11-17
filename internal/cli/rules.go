package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/josh-billington/pug/internal/rules"
	"github.com/josh-billington/pug/internal/tools"
)

func rulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "rules", Short: "List and install pinned OpenGrep rule packs",
		Long: "Rule packs are upstream OpenGrep rule repositories pinned by commit and SHA-256.\nPug downloads a pack only when you run pug rules install; scans never use the network.\nSelect installed packs with pug scan --rules.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(rulesListCommand(), rulesInstallCommand())
	return cmd
}

type packStatus struct {
	Name            string   `json:"name"`
	Repo            string   `json:"repo"`
	Commit          string   `json:"commit"`
	License         string   `json:"license"`
	DefaultProfile  string   `json:"default_profile,omitempty"`
	Installed       bool     `json:"installed"`
	InstalledCommit string   `json:"installed_commit,omitempty"`
	Profiles        []string `json:"profiles"`
	Path            string   `json:"path"`
}

func rulesListCommand() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List rule packs, their pins, profiles, and install state as JSON", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			home, err := tools.Home()
			if err != nil {
				return err
			}
			statuses := []packStatus{}
			for _, p := range rules.Packs {
				status := packStatus{
					Name: p.Name, Repo: p.Repo, Commit: p.Commit, License: p.License, DefaultProfile: p.DefaultProfile,
					Installed: rules.Installed(home, p), Profiles: rules.Profiles(home, p), Path: rules.Dir(home, p.Name),
				}
				if m, err := rules.ReadManifest(home, p); err == nil {
					status.InstalledCommit = m.Commit
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
		Use: "install PACK...", Short: "Download, verify, and install pinned rule packs",
		Example: "  pug rules install amplify\n  pug scan . --checks source --rules amplify:security-audit",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageError("rules install requires at least one pack: %s", strings.Join(rules.Names(), ", "))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if timeout <= 0 {
				return usageError("timeout must be positive")
			}
			packs := make([]rules.Pack, 0, len(args))
			for _, name := range args {
				p, ok := rules.Lookup(name)
				if !ok {
					return usageError("unknown rule pack %q; available: %s", name, strings.Join(rules.Names(), ", "))
				}
				packs = append(packs, p)
			}
			home, err := tools.Home()
			if err != nil {
				return usageError("%v", err)
			}
			out := cmd.OutOrStdout()
			failed := false
			for _, p := range packs {
				ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
				m, changed, err := rules.Install(ctx, &http.Client{}, home, p)
				cancel()
				if err != nil {
					failed = true
					fmt.Fprintf(cmd.ErrOrStderr(), "pug: %s: %v\n", p.Name, err)
					continue
				}
				state := "already installed"
				if changed {
					state = "installed"
				}
				fmt.Fprintf(out, "%s: %s at %s, %d rule files, in %s\n", p.Name, state, m.Commit[:12], m.RuleFiles, rules.Dir(home, p.Name))
				fmt.Fprintf(out, "  License: %s. Review the upstream terms in %s before use.\n", p.License, "https://github.com/"+p.Repo)
			}
			if cmd.Context().Err() != nil {
				return &exitError{code: 130, message: "rule pack installation cancelled. Rerun pug rules install to continue"}
			}
			if failed {
				return &exitError{code: 1, message: "rule pack installation failed"}
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Timeout per pack download and extraction")
	return cmd
}
