package tools

import (
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	t.Parallel()
	input := "\x1b[31mred\x1b[0m\x1b]0;title\x07 a\tb\nc\x00d"
	if got := Sanitize(input); got != "red a b c d" {
		t.Fatalf("Sanitize = %q", got)
	}
	if got := SanitizeText(input); got != "red a\tb\nc d" {
		t.Fatalf("SanitizeText = %q", got)
	}
	if got := Summarize("  a \n\n b  ", 300); got != "a b" {
		t.Fatalf("Summarize = %q", got)
	}
	if got := Summarize(strings.Repeat("é", 10), 5); got != "éé..." {
		t.Fatalf("Summarize split a rune: %q", got)
	}
}

func TestVersionProbe(t *testing.T) {
	t.Parallel()
	if got := VersionArgs("nuclei"); got[0] != "-version" {
		t.Fatalf("nuclei args = %v", got)
	}
	if got := VersionArgs("trivy"); got[0] != "--version" {
		t.Fatalf("trivy args = %v", got)
	}
	if got := VersionLine([]byte("\nVersion: 1.2\nDB: x\n"), nil); got != "Version: 1.2" {
		t.Fatalf("stdout version = %q", got)
	}
	if got := VersionLine([]byte(" \n"), []byte("\x1b[34m[INF]\x1b[0m Nuclei Engine Version: v3.4.0\n")); got != "[INF] Nuclei Engine Version: v3.4.0" {
		t.Fatalf("stderr fallback = %q", got)
	}
}

func TestVersionLineSkipsBanner(t *testing.T) {
	t.Parallel()
	if got := VersionLine(nil, []byte("  __\n / _ \\\n[INF] Current Version: 2.7.0\n")); got != "[INF] Current Version: 2.7.0" {
		t.Fatalf("banner chosen as version: %q", got)
	}
	if got := VersionLine([]byte("8.30.1\n"), nil); got != "8.30.1" {
		t.Fatalf("bare version lost: %q", got)
	}
}
