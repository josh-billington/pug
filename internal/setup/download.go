package setup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

const maxDownload = 256 << 20

func download(ctx context.Context, client *http.Client, url, digest string, destination io.Writer) error {
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
	n, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(response.Body, maxDownload+1))
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if n > maxDownload {
		return fmt.Errorf("download exceeds 256 MiB")
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("SHA-256 mismatch; refusing to install")
	}
	return nil
}
