package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type tarEntry struct {
	name, body string
	link       string
}

func tarball(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		header := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.link != "" {
			header.Typeflag, header.Linkname, header.Size = tar.TypeSymlink, e.link, 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil && e.link == "" {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type archiveTransport struct {
	archive  []byte
	requests atomic.Int64
}

func (s *archiveTransport) RoundTrip(*http.Request) (*http.Response, error) {
	s.requests.Add(1)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(s.archive)), Header: http.Header{}}, nil
}

func (s *archiveTransport) client() *http.Client { return &http.Client{Transport: s} }

func fixturePack(archive []byte) Pack {
	return Pack{
		Name: "fixture", Repo: "example/rules", Commit: strings.Repeat("a", 40), SHA256: digest(archive),
		License: "MIT", RuleDirs: []string{"python"}, ProfilesDir: "configs", DefaultProfile: "default",
	}
}

const ruleYAML = "rules:\n  - id: eval\n    languages: [python]\n    severity: ERROR\n    message: eval\n    pattern: eval(...)\n"

func installedFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, path)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	return files
}

func TestInstallKeepsOnlyRulesProfilesAndLicense(t *testing.T) {
	t.Parallel()
	server := &archiveTransport{archive: tarball(t,
		tarEntry{name: "rules-abc/LICENSE", body: "MIT"},
		tarEntry{name: "rules-abc/README.md", body: "readme"},
		tarEntry{name: "rules-abc/configs/default.list", body: "python/eval.yaml:eval\n"},
		tarEntry{name: "rules-abc/python/eval.yaml", body: ruleYAML},
		tarEntry{name: "rules-abc/python/eval.py", body: "eval(x)\n"},
		tarEntry{name: "rules-abc/python/eval.test.yaml", body: ruleYAML},
		tarEntry{name: "rules-abc/python/eval.fixed.yaml", body: ruleYAML},
		tarEntry{name: "rules-abc/python/metadata.yml", body: "web_frameworks: [flask]\n"},
		tarEntry{name: "rules-abc/python/broken.yml", body: "rules: [\n"},
		tarEntry{name: "rules-abc/python/link.yaml", link: "/etc/passwd"},
		tarEntry{name: "rules-abc/stats/eval.yaml", body: ruleYAML},
	)}
	home := t.TempDir()
	pack := fixturePack(server.archive)
	m, changed, err := Install(t.Context(), server.client(), home, pack)
	if err != nil || !changed || m.RuleFiles != 1 || m.Commit != pack.Commit {
		t.Fatalf("install = %+v, changed %t, %v", m, changed, err)
	}
	want := []string{"LICENSE", "configs/default.list", "manifest.json", "python/eval.yaml"}
	if got := installedFiles(t, Dir(home, pack.Name)); !slices.Equal(got, want) {
		t.Fatalf("installed %v, want %v", got, want)
	}
	if !Installed(home, pack) || !slices.Equal(Profiles(home, pack), []string{"default"}) {
		t.Fatalf("installed pack not recognised: profiles %v", Profiles(home, pack))
	}
	if _, changed, err := Install(t.Context(), server.client(), home, pack); err != nil || changed || server.requests.Load() != 1 {
		t.Fatalf("second install was not a no-op: changed %t, requests %d, %v", changed, server.requests.Load(), err)
	}
	if entries, _ := os.ReadDir(filepath.Join(home, "rules")); len(entries) != 1 {
		t.Fatalf("install left temporary directories: %v", entries)
	}
}

func TestInstallReplacesAnOlderPin(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	old := &archiveTransport{archive: tarball(t, tarEntry{name: "r/python/old.yaml", body: ruleYAML})}
	if _, _, err := Install(t.Context(), old.client(), home, fixturePack(old.archive)); err != nil {
		t.Fatal(err)
	}
	current := &archiveTransport{archive: tarball(t, tarEntry{name: "r/python/new.yaml", body: ruleYAML})}
	pack := fixturePack(current.archive)
	pack.Commit = strings.Repeat("b", 40)
	if Installed(home, pack) {
		t.Fatal("a different pin counts as installed")
	}
	if _, changed, err := Install(t.Context(), current.client(), home, pack); err != nil || !changed {
		t.Fatalf("reinstall: changed %t, %v", changed, err)
	}
	if got := installedFiles(t, Dir(home, pack.Name)); !slices.Equal(got, []string{"manifest.json", "python/new.yaml"}) {
		t.Fatalf("old pin's files survived: %v", got)
	}
}

func TestInstallRefusesBadArchives(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		archive []byte
		digest  string
		message string
	}{
		{name: "digest mismatch", archive: tarball(t, tarEntry{name: "r/python/eval.yaml", body: ruleYAML}), digest: strings.Repeat("0", 64), message: "SHA-256"},
		{name: "duplicate rule ids", archive: tarball(t, tarEntry{name: "r/python/dup.yaml", body: ruleYAML + "  - id: eval\n    pattern: x\n"}), message: "python/dup.yaml"},
		{name: "path escape", archive: tarball(t, tarEntry{name: "r/python/../../escape.yaml", body: ruleYAML}), message: "escapes"},
		{name: "oversized rule file", archive: tarball(t, tarEntry{name: "r/python/big.yaml", body: ruleYAML + "# " + strings.Repeat("x", maxEntry)}), message: "exceeds"},
		{name: "no rules", archive: tarball(t, tarEntry{name: "r/README.md", body: "readme"}), message: "no rule files"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			server := &archiveTransport{archive: tt.archive}
			pack := fixturePack(tt.archive)
			if tt.digest != "" {
				pack.SHA256 = tt.digest
			}
			_, _, err := Install(t.Context(), server.client(), home, pack)
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("error = %v, want mention of %q", err, tt.message)
			}
			if entries, _ := os.ReadDir(filepath.Join(home, "rules")); len(entries) != 0 {
				t.Fatalf("failed install left files: %v", entries)
			}
		})
	}
}

func TestInstallRemovesOnlyStaleTemporaryDirectories(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	parent := filepath.Join(home, "rules")
	stale, fresh := filepath.Join(parent, ".tmp.fixture.crashed"), filepath.Join(parent, ".tmp.fixture.running")
	other := filepath.Join(parent, ".tmp.fixture-two.crashed")
	for _, dir := range []string{stale, fresh, other} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleAfter)
	for _, dir := range []string{stale, other} {
		if err := os.Chtimes(dir, old, old); err != nil {
			t.Fatal(err)
		}
	}
	server := &archiveTransport{archive: tarball(t, tarEntry{name: "r/python/eval.yaml", body: ruleYAML})}
	if _, _, err := Install(t.Context(), server.client(), home, fixturePack(server.archive)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale directory kept: %v", err)
	}
	for _, dir := range []string{fresh, other} {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("%s removed: %v", dir, err)
		}
	}
}

func TestInstallBoundsSkippedEntryExpansion(t *testing.T) {
	t.Parallel()
	var archive bytes.Buffer
	compressed := gzip.NewWriter(&archive)
	writer := tar.NewWriter(compressed)
	const skipped = maxDecompressed + 1<<20
	if err := writer.WriteHeader(&tar.Header{Name: "r/ignored.bin", Mode: 0o600, Size: skipped}); err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 1<<20)
	for written := 0; written < skipped; written += len(block) {
		if _, err := writer.Write(block); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.WriteHeader(&tar.Header{Name: "r/python/eval.yaml", Mode: 0o600, Size: int64(len(ruleYAML))}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, ruleYAML); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	server := &archiveTransport{archive: archive.Bytes()}
	_, _, err := Install(t.Context(), server.client(), t.TempDir(), fixturePack(server.archive))
	if !errors.Is(err, errArchiveTooLarge) {
		t.Fatalf("error = %v, want the archive expansion limit", err)
	}
}
