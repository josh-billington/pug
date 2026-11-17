package tools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDownloadVerifiesPinnedDigestAndHTTPStatus(t *testing.T) {
	body := []byte("verified upstream binary")
	hash := sha256.Sum256(body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(body)
	}))
	defer server.Close()
	for _, tc := range []struct {
		path, digest string
		valid        bool
	}{
		{"/binary", hex.EncodeToString(hash[:]), true},
		{"/binary", strings.Repeat("0", 64), false},
		{"/missing", hex.EncodeToString(hash[:]), false},
	} {
		var output bytes.Buffer
		err := Download(t.Context(), server.Client(), server.URL+tc.path, tc.digest, &output)
		if (err == nil) != tc.valid {
			t.Fatalf("download %s: %v", tc.path, err)
		}
	}
}
