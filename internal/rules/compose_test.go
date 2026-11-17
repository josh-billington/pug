package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func ruleFile(ids ...string) *fstest.MapFile {
	var b strings.Builder
	b.WriteString("rules:\n")
	for _, id := range ids {
		b.WriteString("  - id: " + id + "\n    languages: [python]\n    severity: WARNING\n    message: " + id + " found\n    pattern: " + strings.ReplaceAll(id, "-", "_") + "(...)\n")
	}
	return &fstest.MapFile{Data: []byte(b.String())}
}

func testPack() (Pack, fstest.MapFS) {
	pack := Pack{
		Name: "amp", Repo: "example/rules", Commit: strings.Repeat("c", 40), SHA256: strings.Repeat("d", 64),
		License: "MIT", RuleDirs: []string{"python", "go"}, ProfilesDir: "configs", DefaultProfile: "default",
	}
	files := fstest.MapFS{
		"python/lang/eval.yaml":       ruleFile("eval", "eval-in-loop"),
		"python/flask/debug.yml":      ruleFile("debug-enabled"),
		"go/lang/exec.yaml":           ruleFile("exec"),
		"configs/default.list":        {Data: []byte("python/lang/eval.yaml:eval\npython/flask/debug.yaml:debug-enabled\n\n# comment\npython/lang/eval.yaml:missing-id\ntrailofbits/go/x.yaml:x\nnot-an-entry\n")},
		"configs/security-audit.list": {Data: []byte("python/lang/eval.yaml:eval\ngo/lang/exec.yaml:exec\n")},
	}
	return pack, files
}

func ids(t *testing.T, r Ruleset) []string {
	t.Helper()
	rules, err := parseRules(r.Config)
	if err != nil {
		t.Fatalf("composed config does not parse: %v\n%s", err, r.Config)
	}
	var got []string
	for _, rule := range rules {
		got = append(got, rule.id)
	}
	return got
}

func packSource(pack Pack, files fstest.MapFS, profile string) Source {
	return Source{Spec: Spec{Kind: PackSpec, Pack: pack, Profile: profile}, Files: files, Commit: pack.Commit}
}

func TestComposeQualifiesPackRulesAndRecordsUnresolvedEntries(t *testing.T) {
	t.Parallel()
	pack, files := testPack()
	r, err := Compose([]Source{packSource(pack, files, "")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"amp.python.flask.debug.debug-enabled", "amp.python.lang.eval"}
	if got := ids(t, r); !slices.Equal(got, want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	p := r.Provenance
	wantUnresolved := []string{"amp:default python/lang/eval.yaml:missing-id", "amp:default trailofbits/go/x.yaml:x", "amp:default not-an-entry"}
	if !slices.Equal(p.Unresolved, wantUnresolved) {
		t.Fatalf("unresolved = %q, want %q", p.Unresolved, wantUnresolved)
	}
	if !slices.Equal(p.Specs, []string{"amp:default"}) || p.Packs["amp"] != pack.Commit || p.Rules != 2 || p.SHA256 == "" {
		t.Fatalf("provenance = %+v", p)
	}
}

func TestComposeWithoutProfileTakesEveryRuleFile(t *testing.T) {
	t.Parallel()
	pack, files := testPack()
	pack.ProfilesDir, pack.DefaultProfile = "", ""
	r, err := Compose([]Source{packSource(pack, files, "")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"amp.go.lang.exec", "amp.python.flask.debug.debug-enabled", "amp.python.lang.eval", "amp.python.lang.eval.eval-in-loop"}
	if got := ids(t, r); !slices.Equal(got, want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
}

func TestComposeUnionsOverlappingSpecsIndependentOfOrder(t *testing.T) {
	t.Parallel()
	pack, files := testPack()
	_, otherFiles := testPack()
	forward, err := Compose([]Source{packSource(pack, files, "default"), packSource(pack, otherFiles, "security-audit")})
	if err != nil {
		t.Fatal(err)
	}
	_, files = testPack()
	_, otherFiles = testPack()
	backward, err := Compose([]Source{packSource(pack, files, "security-audit"), packSource(pack, otherFiles, "default")})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"amp.go.lang.exec", "amp.python.flask.debug.debug-enabled", "amp.python.lang.eval"}
	if got := ids(t, forward); !slices.Equal(got, want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	if string(forward.Config) != string(backward.Config) || forward.Provenance.SHA256 != backward.Provenance.SHA256 {
		t.Fatal("spec order changed the composed config")
	}
}

func TestComposeKeepsStarterAndFileIDs(t *testing.T) {
	t.Parallel()
	team := fstest.MapFS{"team.yml": ruleFile("team-rule")}
	sources := []Source{
		{Spec: Spec{Kind: StarterSpec}, Files: starterFS, File: "starter.yml"},
		{Spec: Spec{Kind: FileSpec, Path: "/rules/team.yml"}, Files: team, File: "team.yml"},
	}
	r, err := Compose(sources)
	if err != nil {
		t.Fatal(err)
	}
	got := ids(t, r)
	if !slices.Contains(got, "team-rule") || !slices.Contains(got, "javascript-eval") || len(got) != 5 {
		t.Fatalf("ids = %v", got)
	}
	if !slices.Equal(r.Provenance.Specs, []string{"starter", "/rules/team.yml"}) || r.Provenance.Packs != nil {
		t.Fatalf("provenance = %+v", r.Provenance)
	}
}

func TestComposeRejectsConflictsAndBadInput(t *testing.T) {
	t.Parallel()
	pack, files := testPack()
	conflict := fstest.MapFS{"a.yml": ruleFile("javascript-eval")}
	identical := fstest.MapFS{"a.yml": ruleFile("same"), "b.yml": ruleFile("same")}
	cases := []struct {
		name    string
		sources []Source
		message string
	}{
		{name: "different rule with a taken id", sources: []Source{
			{Spec: Spec{Kind: StarterSpec}, Files: starterFS, File: "starter.yml"},
			{Spec: Spec{Kind: FileSpec, Path: "a.yml"}, Files: conflict, File: "a.yml"},
		}, message: `"javascript-eval" from a.yml conflicts`},
		{name: "unknown profile", sources: []Source{packSource(pack, files, "nope")}, message: "profiles: default, security-audit"},
		{name: "not a rules file", sources: []Source{{Spec: Spec{Kind: FileSpec, Path: "x.yml"}, Files: fstest.MapFS{"x.yml": {Data: []byte("key: value\n")}}, File: "x.yml"}}, message: "not an OpenGrep rules file"},
		{name: "missing file", sources: []Source{{Spec: Spec{Kind: FileSpec, Path: "x.yml"}, Files: fstest.MapFS{}, File: "x.yml"}}, message: "x.yml"},
		{name: "no rules", sources: []Source{{Spec: Spec{Kind: FileSpec, Path: "x.yml"}, Files: fstest.MapFS{"x.yml": {Data: []byte("rules: []\n")}}, File: "x.yml"}}, message: "no rules"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Compose(tt.sources); err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("error = %v, want mention of %q", err, tt.message)
			}
		})
	}
	r, err := Compose([]Source{
		{Spec: Spec{Kind: FileSpec, Path: "a.yml"}, Files: identical, File: "a.yml"},
		{Spec: Spec{Kind: FileSpec, Path: "b.yml"}, Files: identical, File: "b.yml"},
	})
	if err != nil || r.Provenance.Rules != 1 {
		t.Fatalf("identical rules not unioned: %+v, %v", r.Provenance, err)
	}
}

func TestResolveReportsMissingPacksOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	pack, _ := testPack()
	installed := pack
	installed.Name = "installed"
	dir := Dir(home, installed.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(Manifest{Pack: installed.Name, Commit: installed.Commit, SHA256: installed.SHA256})
	if err := os.WriteFile(filepath.Join(dir, manifestName), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	specs := []Spec{{Kind: PackSpec, Pack: pack}, {Kind: PackSpec, Pack: pack, Profile: "secrets"}, {Kind: PackSpec, Pack: installed}, {Kind: StarterSpec}}
	sources, missing, err := Resolve(specs)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(missing, []string{"amp"}) || len(sources) != 2 || sources[0].Commit != installed.Commit {
		t.Fatalf("missing = %v, sources = %+v", missing, sources)
	}
}

func TestComposeKeepsEachFilesAliasesSelfContained(t *testing.T) {
	t.Parallel()
	rule := func(id, value string) string {
		return "  - id: " + id + "\n    languages: [python]\n    severity: ERROR\n    message: " + id + "\n    pattern: " + value + "\n"
	}
	files := fstest.MapFS{
		"first.yml":  {Data: []byte("rules:\n" + rule("z-eval", "&common eval(...)") + rule("a-eval", "*common"))},
		"second.yml": {Data: []byte("rules:\n" + rule("b-exec", "&common exec(...)") + rule("y-exec", "*common"))},
	}
	r, err := Compose([]Source{
		{Spec: Spec{Kind: FileSpec, Path: "/first.yml"}, Files: files, File: "first.yml"},
		{Spec: Spec{Kind: FileSpec, Path: "/second.yml"}, Files: files, File: "second.yml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := parseRules(r.Config)
	if err != nil {
		t.Fatalf("composed config does not parse: %v\n%s", err, r.Config)
	}
	want := map[string]string{"a-eval": "eval(...)", "z-eval": "eval(...)", "b-exec": "exec(...)", "y-exec": "exec(...)"}
	for _, rule := range rules {
		if got := mappingValue(rule.node, "pattern").Value; got != want[rule.id] {
			t.Errorf("%s pattern = %q, want %q", rule.id, got, want[rule.id])
		}
	}
	if strings.ContainsAny(string(r.Config), "&*") {
		t.Fatalf("composed config still has anchors or aliases:\n%s", r.Config)
	}
}

func TestParseRulesBoundsAliasExpansion(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 9; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [*a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d]\n", i, i, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1)
	}
	b.WriteString("rules: [*a8]\n")
	if _, err := parseRules([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "expand beyond") {
		t.Fatalf("error = %v, want alias expansion limit", err)
	}
}

func TestParseRulesRejectsRulesInLaterDocuments(t *testing.T) {
	t.Parallel()
	data := string(ruleFile("first").Data) + "---\n" + string(ruleFile("second").Data)
	if _, err := parseRules([]byte(data)); err == nil || errors.Is(err, errNotRules) {
		t.Fatalf("error = %v, want a hard error for a second document", err)
	}
	if _, err := parseRules([]byte("kind: Pod\n---\nkind: Service\n")); !errors.Is(err, errNotRules) {
		t.Fatalf("error = %v, want multi-document non-rule YAML skipped", err)
	}
}
