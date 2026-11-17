package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

// MaxDownload caps every artifact Pug downloads.
const MaxDownload = 256 << 20

// Download streams url into destination and fails unless its SHA-256 is digest.
// Callers must discard what was written when it returns an error.
func Download(ctx context.Context, client *http.Client, url, digest string, destination io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
	n, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(response.Body, MaxDownload+1))
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if n > MaxDownload {
		return fmt.Errorf("download exceeds 256 MiB")
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("SHA-256 mismatch; refusing to install")
	}
	return nil
}
