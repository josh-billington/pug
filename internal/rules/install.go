package rules

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/josh-billington/pug/internal/tools"
)

const (
	manifestName = "manifest.json"
	maxEntry     = 1 << 20
	// maxArchive bounds the whole decompressed tar stream, including entries
	// extract skips, which tar still inflates to reach the next header.
	maxArchive = 64 << 20
	// A temporary directory this old cannot belong to a running install.
	staleAfter = time.Hour
)

// Manifest records what an installed pack directory holds. Install writes it
// last, so its presence marks a complete install.
type Manifest struct {
	Pack      string `json:"pack"`
	Repo      string `json:"repo"`
	Commit    string `json:"commit"`
	SHA256    string `json:"sha256"`
	License   string `json:"license"`
	RuleFiles int    `json:"rule_files"`
}

// Dir is where the pack is installed under Pug's home.
func Dir(home, name string) string { return filepath.Join(home, "rules", name) }

// ReadManifest returns the installed pack's manifest.
func ReadManifest(home string, p Pack) (Manifest, error) {
	data, err := os.ReadFile(filepath.Join(Dir(home, p.Name), manifestName))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("decode %s manifest: %w", p.Name, err)
	}
	return m, nil
}

// Installed reports whether the pack's pinned commit is installed.
func Installed(home string, p Pack) bool {
	m, err := ReadManifest(home, p)
	return err == nil && m.Commit == p.Commit && m.SHA256 == p.SHA256
}

// Profiles lists the profile names an installed pack provides.
func Profiles(home string, p Pack) []string {
	if p.ProfilesDir == "" {
		return []string{}
	}
	entries, err := os.ReadDir(filepath.Join(Dir(home, p.Name), p.ProfilesDir))
	if err != nil {
		return []string{}
	}
	profiles := []string{}
	for _, entry := range entries {
		if name, ok := strings.CutSuffix(entry.Name(), ".list"); ok && entry.Type().IsRegular() {
			profiles = append(profiles, name)
		}
	}
	sort.Strings(profiles)
	return profiles
}

// Install downloads the pinned tarball, verifies its digest, and replaces the
// pack directory with only its rule files, profiles, and license. It does
// nothing when the pinned commit is already installed, and reports whether
// it changed anything.
func Install(ctx context.Context, client *http.Client, home string, p Pack) (Manifest, bool, error) {
	if !p.Pinned() {
		return Manifest{}, false, fmt.Errorf("rule pack %s is not pinned", p.Name)
	}
	if m, err := ReadManifest(home, p); err == nil && m.Commit == p.Commit && m.SHA256 == p.SHA256 {
		return m, false, nil
	}
	parent := filepath.Join(home, "rules")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return Manifest{}, false, err
	}
	if err := removeStale(parent, p.Name); err != nil {
		return Manifest{}, false, err
	}
	work, err := os.MkdirTemp(parent, ".tmp."+p.Name+".*")
	if err != nil {
		return Manifest{}, false, err
	}
	defer os.RemoveAll(work)
	archive, err := os.Create(filepath.Join(work, "pack.tar.gz"))
	if err != nil {
		return Manifest{}, false, err
	}
	defer archive.Close()
	if err := tools.Download(ctx, client, p.TarballURL(), p.SHA256, archive); err != nil {
		return Manifest{}, false, fmt.Errorf("download %s: %w", p.Name, err)
	}
	tree := filepath.Join(work, "tree")
	if err := os.Mkdir(tree, 0o700); err != nil {
		return Manifest{}, false, err
	}
	count, err := extract(archive, tree, p)
	if err != nil {
		return Manifest{}, false, fmt.Errorf("extract %s: %w", p.Name, err)
	}
	m := Manifest{Pack: p.Name, Repo: p.Repo, Commit: p.Commit, SHA256: p.SHA256, License: p.License, RuleFiles: count}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, false, err
	}
	if err := os.WriteFile(filepath.Join(tree, manifestName), append(data, '\n'), 0o600); err != nil {
		return Manifest{}, false, err
	}
	// Move any previous install aside inside work, so the deferred removal
	// deletes it and an interrupted swap leaves only a stale temp directory.
	destination := Dir(home, p.Name)
	if err := os.Rename(destination, filepath.Join(work, "previous")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, false, err
	}
	if err := os.Rename(tree, destination); err != nil {
		return Manifest{}, false, err
	}
	return m, true, nil
}

func removeStale(parent, name string) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".tmp."+name+".") {
			continue
		}
		info, err := entry.Info()
		if err != nil || time.Since(info.ModTime()) < staleAfter {
			continue
		}
		if err := os.RemoveAll(filepath.Join(parent, entry.Name())); err != nil {
			return fmt.Errorf("remove stale install directory: %w", err)
		}
	}
	return nil
}

type entryKind int

const (
	skipEntry entryKind = iota
	ruleEntry
	plainEntry
)

// classify decides what install keeps from a pack-relative archive path.
// Test fixtures (*.test.yaml, *.fixed.*) look like rules and break a config.
func classify(p Pack, rel string) entryKind {
	if rel == "LICENSE" {
		return plainEntry
	}
	if p.ProfilesDir != "" && path.Dir(rel) == p.ProfilesDir && path.Ext(rel) == ".list" {
		return plainEntry
	}
	top, _, _ := strings.Cut(rel, "/")
	base := path.Base(rel)
	ext := path.Ext(rel)
	if slices.Contains(p.RuleDirs, top) && (ext == ".yml" || ext == ".yaml") && !strings.Contains(base, ".test.") && !strings.Contains(base, ".fixed.") {
		return ruleEntry
	}
	return skipEntry
}

// extract copies kept regular files into tree through os.Root, so no archive
// path, link, or permission can place a file outside it.
func extract(archive *os.File, tree string, p Pack) (int, error) {
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	root, err := os.OpenRoot(tree)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	reader := tar.NewReader(&budgetReader{r: gz, left: maxArchive})
	count := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return count, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		// GitHub archives put everything under one "<repo>-<commit>/" directory.
		_, rel, ok := strings.Cut(header.Name, "/")
		if !ok {
			continue
		}
		kind := classify(p, rel)
		if kind == skipEntry {
			continue
		}
		if !fs.ValidPath(rel) {
			return count, fmt.Errorf("archive path %q escapes the pack", header.Name)
		}
		if header.Size > maxEntry {
			return count, fmt.Errorf("%s exceeds %d bytes", rel, maxEntry)
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxEntry))
		if err != nil {
			return count, err
		}
		if kind == ruleEntry {
			_, err := parseRules(data)
			if errors.Is(err, errNotRules) {
				continue
			}
			if err != nil {
				return count, fmt.Errorf("%s: %w", rel, err)
			}
			count++
		}
		if err := root.MkdirAll(filepath.FromSlash(path.Dir(rel)), 0o700); err != nil {
			return count, err
		}
		if err := root.WriteFile(filepath.FromSlash(rel), data, 0o600); err != nil {
			return count, err
		}
	}
	if count == 0 {
		return 0, fmt.Errorf("archive contains no rule files")
	}
	return count, nil
}

var errArchiveTooLarge = fmt.Errorf("pack archive expands beyond %d bytes", maxArchive)

// budgetReader fails rather than reporting EOF once its budget is spent, so an
// oversized archive is an error instead of a silently truncated pack.
type budgetReader struct {
	r    io.Reader
	left int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errArchiveTooLarge
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}
