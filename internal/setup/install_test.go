package setup

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
)

func TestExtractCopiesOnlyBinaryAndRejectsLinks(t *testing.T) {
	for _, tc := range []struct {
		format string
		link   bool
	}{
		{".tar.gz", false}, {".tar.gz", true}, {".zip", false}, {".zip", true}, {"raw", false},
	} {
		var data bytes.Buffer
		payload := []byte("executable bytes")
		switch tc.format {
		case ".tar.gz":
			gz := gzip.NewWriter(&data)
			tw := tar.NewWriter(gz)
			typeflag := byte(tar.TypeReg)
			if tc.link {
				typeflag = tar.TypeSymlink
			}
			tw.WriteHeader(&tar.Header{Name: "../../elsewhere/tool", Typeflag: typeflag, Size: int64(len(payload))})
			if !tc.link {
				tw.Write(payload)
			}
			tw.Close()
			gz.Close()
		case ".zip":
			zw := zip.NewWriter(&data)
			header := &zip.FileHeader{Name: "../../elsewhere/tool"}
			header.SetMode(0o755)
			if tc.link {
				header.SetMode(os.ModeSymlink | 0o777)
			}
			w, err := zw.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			w.Write(payload)
			zw.Close()
		default:
			data.Write(payload)
		}
		file, err := os.CreateTemp(t.TempDir(), "archive")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(data.Bytes()); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err = extract(file, "release"+tc.format, "tool", &output)
		file.Close()
		if tc.link {
			if err == nil || output.Len() != 0 {
				t.Fatalf("extracted archive link in %s", tc.format)
			}
		} else if err != nil || !bytes.Equal(output.Bytes(), payload) {
			t.Fatalf("invalid extraction in %s: %q, %v", tc.format, output.Bytes(), err)
		}
	}
}

func TestReleaseCatalogCoversSupportedPlatforms(t *testing.T) {
	for _, name := range append(append([]string{}, NativeTools[:5]...), "uv") {
		for _, platform := range []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"} {
			a, err := release(name, platform)
			if err != nil || !strings.HasPrefix(a.URL, "https://github.com/") || len(a.SHA256) != 64 {
				t.Fatalf("invalid pinned release %s/%s: %+v, %v", name, platform, a, err)
			}
			if _, err := hex.DecodeString(a.SHA256); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := release("trivy", "windows/amd64"); err == nil {
		t.Fatal("unsupported platform accepted")
	}
	if err := copyBinary(io.Discard, strings.NewReader("")); err == nil {
		t.Fatal("empty executable accepted")
	}
}
