package rules

import (
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

func testPack() (string, fstest.MapFS) {
	pack := "amp"
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

func packSource(pack string, files fstest.MapFS, profile string) Source {
	return Source{Spec: Spec{Kind: PackSpec, Name: pack, Profile: profile}, Files: files, Name: pack, Commit: strings.Repeat("c", 40)}
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
	wantUnresolved := []string{"amp python/lang/eval.yaml:missing-id", "amp trailofbits/go/x.yaml:x", "amp not-an-entry"}
	if !slices.Equal(p.Unresolved, wantUnresolved) {
		t.Fatalf("unresolved = %q, want %q", p.Unresolved, wantUnresolved)
	}
	if !slices.Equal(p.Specs, []string{"amp"}) || p.Packs["amp"] != strings.Repeat("c", 40) || p.Rules != 2 || p.SHA256 == "" {
		t.Fatalf("provenance = %+v", p)
	}
}

func TestComposeWithoutProfileTakesEveryRuleFile(t *testing.T) {
	t.Parallel()
	pack, files := testPack()
	delete(files, "configs/default.list")
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
		{Spec: Spec{Kind: PathSpec, Path: "/rules/team.yml"}, Files: team, File: "team.yml"},
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
			{Spec: Spec{Kind: PathSpec, Path: "a.yml"}, Files: conflict, File: "a.yml"},
		}, message: `"javascript-eval" from a.yml conflicts`},
		{name: "unknown profile", sources: []Source{packSource(pack, files, "nope")}, message: "profiles: default, security-audit"},
		{name: "not a rules file", sources: []Source{{Spec: Spec{Kind: PathSpec, Path: "x.yml"}, Files: fstest.MapFS{"x.yml": {Data: []byte("key: value\n")}}, File: "x.yml"}}, message: "not an OpenGrep rules file"},
		{name: "missing file", sources: []Source{{Spec: Spec{Kind: PathSpec, Path: "x.yml"}, Files: fstest.MapFS{}, File: "x.yml"}}, message: "x.yml"},
		{name: "no rules", sources: []Source{{Spec: Spec{Kind: PathSpec, Path: "x.yml"}, Files: fstest.MapFS{"x.yml": {Data: []byte("rules: []\n")}}, File: "x.yml"}}, message: "no rules"},
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
		{Spec: Spec{Kind: PathSpec, Path: "a.yml"}, Files: identical, File: "a.yml"},
		{Spec: Spec{Kind: PathSpec, Path: "b.yml"}, Files: identical, File: "b.yml"},
	})
	if err != nil || r.Provenance.Rules != 1 {
		t.Fatalf("identical rules not unioned: %+v, %v", r.Provenance, err)
	}
}

func TestResolveReportsMissingPacksOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	pack, _ := testPack()
	installed := "installed"
	dir := Dir(home, installed)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	specs := []Spec{{Kind: PackSpec, Name: pack}, {Kind: PackSpec, Name: pack, Profile: "secrets"}, {Kind: PackSpec, Name: installed}, {Kind: StarterSpec}}
	sources, missing, err := Resolve(specs)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(missing, []string{"amp"}) || len(sources) != 2 || sources[0].Name != installed {
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
		{Spec: Spec{Kind: PathSpec, Path: "/first.yml"}, Files: files, File: "first.yml"},
		{Spec: Spec{Kind: PathSpec, Path: "/second.yml"}, Files: files, File: "second.yml"},
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

func TestComposeDirectoryFiltersFilesBeforeResolvingProfiles(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "mypack")
	valid := map[string]string{
		"team/python/no-eval.yaml": string(ruleFile("no-eval").Data),
		"root.yml":                 string(ruleFile("root").Data),
	}
	skipped := map[string]string{
		".git/hidden.yml":                "rules: [{id: no-eval}, {id: no-eval}]\n",
		".private/hidden.yml":            "rules: [{id: no-eval}, {id: no-eval}]\n",
		"team/.private/hidden.yml":       "rules: [{id: no-eval}, {id: no-eval}]\n",
		"team/python/no-eval.test.yml":   "rules: [{id: no-eval}, {id: no-eval}]\n",
		"team/python/no-eval.test.yaml":  "rules: [{id: no-eval}, {id: no-eval}]\n",
		"team/python/no-eval.fixed.yaml": "rules: [{id: no-eval}, {id: no-eval}]\n",
		"metadata.yaml":                  "kind: Pod\n",
		"README.md":                      "readme\n",
	}
	write := func(name, body string) {
		t.Helper()
		file := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range valid {
		write(name, body)
	}
	for name, body := range skipped {
		write(name, body)
	}
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, ruleFile("outside").Data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct {
		name   string
		target string
	}{
		{name: "link.yaml", target: outside},
		{name: "inside.yaml", target: filepath.Join(dir, "root.yml")},
		{name: "linked-dir", target: filepath.Dir(outside)},
	} {
		if err := os.Symlink(link.target, filepath.Join(dir, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	source := Source{Spec: Spec{Kind: PathSpec, Path: dir}, Name: "mypack", Directory: dir}
	r, err := Compose([]Source{source})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(t, r); !slices.Equal(got, []string{"mypack.root", "mypack.team.python.no-eval"}) {
		t.Fatalf("filtered IDs: %v", got)
	}
	entries := []string{"team/python/no-eval.yml:no-eval"}
	for name := range skipped {
		entries = append(entries, name+":no-eval")
	}
	entries = append(entries, "../outside.yaml:outside", "link.yaml:outside", "inside.yaml:root", "linked-dir/outside.yaml:outside")
	write("configs/default.list", strings.Join(entries, "\n")+"\n")
	r, err = Compose([]Source{source})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(t, r); !slices.Equal(got, []string{"mypack.team.python.no-eval"}) || len(r.Provenance.Unresolved) != len(entries)-1 {
		t.Fatalf("profile filtering: %v, unresolved %v", got, r.Provenance.Unresolved)
	}
}

func TestResolveLocalDirectoryAndProfile(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "mypack")
	if err := os.MkdirAll(filepath.Join(dir, "configs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "eval.yaml"), ruleFile("eval").Data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "configs", "audit.list"), []byte("eval.yaml:eval\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	specs, err := ParseSpecs([]string{dir + ":audit"})
	if err != nil {
		t.Fatal(err)
	}
	sources, missing, err := Resolve(specs)
	if err != nil || len(missing) != 0 {
		t.Fatalf("resolve: %v, %v", missing, err)
	}
	r, err := Compose(sources)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids(t, r), []string{"mypack.eval"}) || !slices.Equal(r.Provenance.Specs, []string{dir + ":audit"}) || r.Provenance.Packs != nil {
		t.Fatalf("directory pack: %+v", r.Provenance)
	}
	if got, err := Profiles(dir); err != nil || !slices.Equal(got, []string{"audit"}) {
		t.Fatalf("profiles = %v, %v", got, err)
	}
}

func TestComposeSkipsProfileSymlinks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "configs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "eval.yaml"), ruleFile("eval").Data, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "default.list")
	if err := os.WriteFile(outside, []byte("../outside.yaml:outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "configs", "default.list")); err != nil {
		t.Fatal(err)
	}
	source := Source{Spec: Spec{Kind: PathSpec, Path: dir}, Name: "mypack", Directory: dir}
	r, err := Compose([]Source{source})
	if err != nil || !slices.Equal(ids(t, r), []string{"mypack.eval"}) {
		t.Fatalf("symlink profile affected default selection: %v", err)
	}
	source.Spec.Profile = "default"
	if _, err := Compose([]Source{source}); err == nil || !strings.Contains(err.Error(), "has no profile") {
		t.Fatalf("symlink profile accepted: %v", err)
	}
}

func TestComposeBoundsRulesFiles(t *testing.T) {
	t.Parallel()
	file := &fstest.MapFile{Data: append(ruleFile("eval").Data, []byte("#"+strings.Repeat("x", maxRulesFile))...)}
	_, err := Compose([]Source{{Spec: Spec{Kind: PackSpec, Name: "mypack"}, Name: "mypack", Files: fstest.MapFS{"large.yml": file}}})
	if err == nil || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("oversized rules accepted: %v", err)
	}
}
