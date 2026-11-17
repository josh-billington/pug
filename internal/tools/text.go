package tools

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ansiEscape matches CSI sequences, OSC sequences (BEL or ST terminated), and
// other two-byte ESC sequences emitted by terminal-aware tools.
var ansiEscape = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])`)

// Sanitize removes ANSI escape sequences and replaces every other control
// character with a space, so untrusted tool output is safe on one line.
func Sanitize(text string) string {
	return sanitize(text, false)
}

// SanitizeText is Sanitize for multi-line output: newlines and tabs are kept.
func SanitizeText(text string) string {
	return sanitize(text, true)
}

func sanitize(text string, layout bool) string {
	text = ansiEscape.ReplaceAllString(text, "")
	return strings.Map(func(r rune) rune {
		if layout && (r == '\n' || r == '\t') {
			return r
		}
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text)
}

// Summarize sanitizes text, collapses whitespace, and truncates it to at most
// limit bytes (plus an ellipsis) without splitting a UTF-8 sequence.
func Summarize(text string, limit int) string {
	text = strings.Join(strings.Fields(Sanitize(text)), " ")
	if len(text) <= limit {
		return text
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}

// VersionArgs returns the arguments that make a scanner print its version.
func VersionArgs(tool string) []string {
	switch tool {
	case "actionlint", "nuclei", "naabu":
		return []string{"-version"}
	}
	return []string{"--version"}
}

// VersionLine returns the first line of a version probe's stdout that mentions a version, else
// its first non-empty line. It falls back to stderr for tools such as nuclei that print versions
// there, and skips banners such as naabu's.
func VersionLine(stdout, stderr []byte) string {
	output := string(stdout)
	if strings.TrimSpace(output) == "" {
		output = string(stderr)
	}
	first := ""
	for _, line := range strings.Split(output, "\n") {
		line = Summarize(line, 300)
		if line != "" && first == "" {
			first = line
		}
		if strings.Contains(strings.ToLower(line), "version") {
			return line
		}
	}
	return first
}
