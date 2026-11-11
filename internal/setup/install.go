package setup

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Release asset digests from the upstream GitHub release API, pinned at build time.
//
//go:embed releases.json
var releaseData []byte

type asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

const maxDownload = 256 << 20

func release(name, platform string) (asset, error) {
	var releases map[string]map[string]asset
	if err := json.Unmarshal(releaseData, &releases); err != nil {
		return asset{}, err
	}
	a, ok := releases[name][platform]
	if !ok {
		return asset{}, fmt.Errorf("automatic installation of %s is unavailable for %s; install it on PATH", name, platform)
	}
	return a, nil
}

func download(ctx context.Context, client *http.Client, a asset, destination io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", response.StatusCode)
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(response.Body, maxDownload+1))
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if n > maxDownload {
		return fmt.Errorf("download exceeds 256 MiB")
	}
	if hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("SHA-256 mismatch; refusing to install")
	}
	return nil
}

// Copy only the named binary, never archive paths, permissions, or symlinks.
func extract(file *os.File, url, name string, destination io.Writer) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if strings.HasSuffix(url, ".tar.gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader := tar.NewReader(gz)
		for {
			header, err := reader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if path.Base(header.Name) == name {
				if header.Typeflag != tar.TypeReg {
					return fmt.Errorf("archive binary is not a regular file")
				}
				return copyBinary(destination, reader)
			}
		}
		return fmt.Errorf("archive contains no %s binary", name)
	}
	if strings.HasSuffix(url, ".zip") {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		reader, err := zip.NewReader(file, info.Size())
		if err != nil {
			return err
		}
		for _, entry := range reader.File {
			if path.Base(entry.Name) != name {
				continue
			}
			if !entry.Mode().IsRegular() {
				return fmt.Errorf("archive binary is not a regular file")
			}
			body, err := entry.Open()
			if err != nil {
				return err
			}
			defer body.Close()
			return copyBinary(destination, body)
		}
		return fmt.Errorf("archive contains no %s binary", name)
	}
	return copyBinary(destination, file)
}

func copyBinary(destination io.Writer, source io.Reader) error {
	n, err := io.Copy(destination, io.LimitReader(source, maxDownload+1))
	if err != nil {
		return err
	}
	if n == 0 || n > maxDownload {
		return fmt.Errorf("binary must contain between 1 byte and 256 MiB")
	}
	return nil
}

func (e engine) installBinary(ctx context.Context, name string) (string, error) {
	a, err := release(name, e.platform)
	if err != nil {
		return "", err
	}
	bin := filepath.Join(e.home, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		return "", err
	}
	archive, err := os.CreateTemp(bin, ".download-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(archive.Name())
	defer archive.Close()
	client := &http.Client{Timeout: 5 * time.Minute}
	if err := download(ctx, client, a, archive); err != nil {
		return "", err
	}
	candidate, err := os.CreateTemp(bin, ".install-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(candidate.Name())
	defer candidate.Close()
	if err := extract(archive, a.URL, name, candidate); err != nil {
		return "", err
	}
	if err := candidate.Chmod(0o700); err != nil {
		return "", err
	}
	if err := candidate.Close(); err != nil {
		return "", err
	}
	if _, err := e.version(ctx, name, candidate.Name()); err != nil {
		return "", fmt.Errorf("downloaded binary did not run: %w", err)
	}
	destination := filepath.Join(bin, name)
	if err := os.Rename(candidate.Name(), destination); err != nil {
		return "", err
	}
	return destination, nil
}
