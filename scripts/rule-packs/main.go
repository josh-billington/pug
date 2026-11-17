// Command rule-packs pins each rule pack in internal/rules/packs.json to its
// upstream HEAD commit and records the SHA-256 of that commit's tarball.
//
//	go run ./scripts/rule-packs            # bump every pack to upstream HEAD
//	go run ./scripts/rule-packs -keep      # re-verify the pinned commits only
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/josh-billington/pug/internal/rules"
)

const maxTarball = 64 << 20

func main() {
	registry := flag.String("registry", "internal/rules/packs.json", "Registry file to rewrite")
	keep := flag.Bool("keep", false, "Keep pinned commits; only recompute their digests")
	flag.Parse()
	if err := run(*registry, *keep); err != nil {
		fmt.Fprintln(os.Stderr, "rule-packs:", err)
		os.Exit(1)
	}
}

func run(registry string, keep bool) error {
	data, err := os.ReadFile(registry)
	if err != nil {
		return err
	}
	packs, err := rules.ParsePacks(data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Minute}
	for i, p := range packs {
		if !keep || p.Commit == "" {
			if p.Commit, err = headCommit(ctx, client, p.Repo); err != nil {
				return fmt.Errorf("%s: %w", p.Name, err)
			}
		}
		tarball, err := get(ctx, client, p.TarballURL(), "")
		if err != nil {
			return fmt.Errorf("%s: %w", p.Name, err)
		}
		sum := sha256.Sum256(tarball)
		digest := hex.EncodeToString(sum[:])
		if keep && packs[i].SHA256 != "" && packs[i].SHA256 != digest {
			return fmt.Errorf("%s: tarball digest changed for pinned commit %s", p.Name, p.Commit)
		}
		p.SHA256 = digest
		uncovered, err := uncoveredDirs(tarball, p)
		if err != nil {
			return fmt.Errorf("%s: %w", p.Name, err)
		}
		if len(uncovered) > 0 {
			fmt.Fprintf(os.Stderr, "%s: top-level directories with YAML outside rule_dirs (review them): %s\n", p.Name, strings.Join(uncovered, ", "))
		}
		fmt.Printf("%s %s %s\n", p.Name, p.Commit, p.SHA256)
		packs[i] = p
	}
	out, err := json.MarshalIndent(packs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(registry, append(out, '\n'), 0o644)
}

func headCommit(ctx context.Context, client *http.Client, repo string) (string, error) {
	body, err := get(ctx, client, "https://api.github.com/repos/"+repo+"/commits/HEAD", "application/vnd.github.sha")
	if err != nil {
		return "", fmt.Errorf("resolve HEAD: %w", err)
	}
	commit := strings.TrimSpace(string(body))
	if len(commit) != 40 {
		return "", fmt.Errorf("resolve HEAD: unexpected response %q", commit)
	}
	return commit, nil
}

func get(ctx context.Context, client *http.Client, url, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned HTTP %d", url, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxTarball+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxTarball {
		return nil, fmt.Errorf("GET %s exceeds %d bytes", url, maxTarball)
	}
	return body, nil
}

// uncoveredDirs names top-level directories holding YAML that the pack's
// rule_dirs leave out, so a new upstream language folder is not missed.
func uncoveredDirs(tarball []byte, p rules.Pack) ([]string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, err
	}
	reader := tar.NewReader(gz)
	found := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		parts := strings.SplitN(header.Name, "/", 3)
		ext := path.Ext(header.Name)
		if len(parts) < 3 || strings.HasPrefix(parts[1], ".") || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		if !slices.Contains(p.RuleDirs, parts[1]) && parts[1] != p.ProfilesDir {
			found[parts[1]] = true
		}
	}
	dirs := make([]string, 0, len(found))
	for dir := range found {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs, nil
}
