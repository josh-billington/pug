package rules

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"go.yaml.in/yaml/v3"
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

type composedConfig struct {
	Rules []struct {
		ID      string `yaml:"id"`
		Pattern string `yaml:"pattern"`
	} `yaml:"rules"`
}

func composed(t *testing.T, r Ruleset) composedConfig {
	t.Helper()
	var config composedConfig
	if err := yaml.Unmarshal(r.Config, &config); err != nil {
		t.Fatalf("composed config does not parse: %v\n%s", err, r.Config)
	}
	return config
}

func ids(t *testing.T, r Ruleset) []string {
	t.Helper()
	got := []string{}
	for _, rule := range composed(t, r).Rules {
		got = append(got, rule.ID)
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
	want := map[string]string{"a-eval": "eval(...)", "z-eval": "eval(...)", "b-exec": "exec(...)", "y-exec": "exec(...)"}
	got := map[string]string{}
	for _, rule := range composed(t, r).Rules {
		got[rule.ID] = rule.Pattern
	}
	if !maps.Equal(got, want) {
		t.Errorf("patterns = %v, want %v", got, want)
	}
	if strings.ContainsAny(string(r.Config), "&*") {
		t.Fatalf("composed config still has anchors or aliases:\n%s", r.Config)
	}
}

func TestComposeBoundsAliasExpansion(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 9; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [*a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d, *a%d]\n", i, i, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1, i-1)
	}
	b.WriteString("rules: [*a8]\n")
	files := fstest.MapFS{"bomb.yml": {Data: []byte(b.String())}}
	if _, err := Compose([]Source{{Spec: Spec{Kind: PathSpec, Path: "/bomb.yml"}, Files: files, File: "bomb.yml"}}); err == nil {
		t.Fatal("alias bomb composed")
	}
}

func TestComposeRejectsRulesInLaterDocuments(t *testing.T) {
	t.Parallel()
	multi := fstest.MapFS{"multi.yml": {Data: []byte(string(ruleFile("first").Data) + "---\n" + string(ruleFile("second").Data))}}
	if _, err := Compose([]Source{{Spec: Spec{Kind: PathSpec, Path: "/multi.yml"}, Files: multi, File: "multi.yml"}}); err == nil {
		t.Fatal("rules file with a second document composed")
	}
	pack := fstest.MapFS{
		"good.yml": ruleFile("good"),
		"k8s.yml":  {Data: []byte("kind: Pod\n---\nkind: Service\n")},
	}
	r, err := Compose([]Source{packSource("team", pack, "")})
	if err != nil {
		t.Fatalf("multi-document non-rule YAML was not skipped: %v", err)
	}
	if got := ids(t, r); !slices.Equal(got, []string{"team.good"}) {
		t.Fatalf("ids = %v, want [team.good]", got)
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

func TestComposeDirectoryRejectsBrokenRulesFiles(t *testing.T) {
	t.Parallel()
	for name, broken := range map[string]string{
		"rule without an id": string(ruleFile("eval").Data) + "  - languages: [python]\n    pattern: x\n",
		"invalid rules YAML": "rules:\n  - id: [\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for file, data := range map[string]string{
				"good.yaml":       string(ruleFile("exec").Data),
				"broken.yaml":     broken,
				"k8s/pod.yaml":    "kind: Pod\n",
				"fixtures/x.yaml": "key: [\n",
			} {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, file)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, file), []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			source := Source{Spec: Spec{Kind: PathSpec, Path: dir}, Name: "mypack", Directory: dir}
			if _, err := Compose([]Source{source}); err == nil || !strings.Contains(err.Error(), "broken.yaml") {
				t.Fatalf("error = %v, want the broken rules file named", err)
			}
			if err := os.Remove(filepath.Join(dir, "broken.yaml")); err != nil {
				t.Fatal(err)
			}
			r, err := Compose([]Source{source})
			if err != nil || !slices.Equal(ids(t, r), []string{"mypack.good.exec"}) {
				t.Fatalf("non-rule YAML was not skipped: %v", err)
			}
		})
	}
}

func TestComposeSkipsSymlinkedProfileDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for file, data := range map[string]string{
		"eval.yaml":            string(ruleFile("eval").Data),
		"exec.yaml":            string(ruleFile("exec").Data),
		".hidden/default.list": "eval.yaml:eval\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, file)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(".hidden", filepath.Join(dir, "configs")); err != nil {
		t.Fatal(err)
	}
	source := Source{Spec: Spec{Kind: PathSpec, Path: dir}, Name: "mypack", Directory: dir}
	r, err := Compose([]Source{source})
	if err != nil || !slices.Equal(ids(t, r), []string{"mypack.eval", "mypack.exec"}) {
		t.Fatalf("symlinked configs directory changed selection: %v %v", ids(t, r), err)
	}
}

func TestComposeSkipsNonMappingYAMLInPacks(t *testing.T) {
	t.Parallel()
	pack := fstest.MapFS{
		"good.yml":       ruleFile("good"),
		"languages.yaml": {Data: []byte("- python\n- go\n")},
	}
	r, err := Compose([]Source{packSource("team", pack, "")})
	if err != nil {
		t.Fatalf("top-level list YAML was not skipped: %v", err)
	}
	if got := ids(t, r); !slices.Equal(got, []string{"team.good"}) {
		t.Fatalf("ids = %v, want [team.good]", got)
	}
}

func TestResolveNamesFoldersInsideAnInstalledPackByPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	body := string(ruleFile("hardcoded-jwt-secret").Data)
	for _, folder := range []string{"javascript/jose/security", "javascript/jsonwebtoken/security"} {
		dir := filepath.Join(home, "rules", "opengrep", filepath.FromSlash(folder))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "jwt-hardcode.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(home, "rules", "opengrep")
	if err := os.WriteFile(filepath.Join(root, "eval.yaml"), ruleFile("eval").Data, 0o600); err != nil {
		t.Fatal(err)
	}
	jose := filepath.Join(root, "javascript", "jose", "security")
	token := filepath.Join(root, "javascript", "jsonwebtoken", "security")
	specs, err := ParseSpecs([]string{jose, token})
	if err != nil {
		t.Fatal(err)
	}
	sources, missing, err := Resolve(specs)
	if err != nil || len(missing) != 0 {
		t.Fatalf("resolve: missing=%v err=%v", missing, err)
	}
	r, err := Compose(sources)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"opengrep.javascript.jose.security.jwt-hardcode.hardcoded-jwt-secret",
		"opengrep.javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
	}
	if got := ids(t, r); !slices.Equal(got, want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	rootSpecs, err := ParseSpecs([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	rootSources, _, err := Resolve(rootSpecs)
	if err != nil {
		t.Fatal(err)
	}
	rootRules, err := Compose(rootSources)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ids(t, rootRules), "opengrep.eval") {
		t.Fatalf("pack root ids = %v", ids(t, rootRules))
	}
}

func TestComposeSelectsALocalProfileFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PUG_HOME", home)
	pack := filepath.Join(home, "rules", "opengrep")
	if err := os.MkdirAll(filepath.Join(pack, "configs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack, "eval.yaml"), ruleFile("eval").Data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack, "exec.yaml"), ruleFile("exec").Data, 0o600); err != nil {
		t.Fatal(err)
	}
	// A pack default would select exec. The local file must win.
	if err := os.WriteFile(filepath.Join(pack, "configs", "default.list"), []byte("exec.yaml:exec\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	list := filepath.Join(t.TempDir(), "security.list")
	if err := os.WriteFile(list, []byte("# security\neval.yaml:eval\nexec.yaml:missing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	specs, err := ParseSpecs([]string{"opengrep:" + list})
	if err != nil {
		t.Fatal(err)
	}
	if specs[0].Kind != PackSpec || specs[0].Name != "opengrep" || specs[0].Profile != "" || specs[0].ProfileFile != list {
		t.Fatalf("spec = %+v", specs[0])
	}
	sources, missing, err := Resolve(specs)
	if err != nil || len(missing) != 0 || len(sources) != 1 {
		t.Fatalf("resolve: missing=%v sources=%d err=%v", missing, len(sources), err)
	}
	r, err := Compose(sources)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(t, r); !slices.Equal(got, []string{"opengrep.eval"}) {
		t.Fatalf("ids = %v", got)
	}
	if len(r.Provenance.Unresolved) != 1 || !strings.Contains(r.Provenance.Unresolved[0], "exec.yaml:missing") {
		t.Fatalf("unresolved = %v", r.Provenance.Unresolved)
	}
	if !slices.Equal(r.Provenance.Specs, []string{"opengrep:" + list}) {
		t.Fatalf("specs = %v", r.Provenance.Specs)
	}
}

func TestComposeRejectsDuplicateRuleIDsInAFile(t *testing.T) {
	t.Parallel()
	pack := fstest.MapFS{
		"good.yml":       ruleFile("good"),
		"python/dup.yml": ruleFile("dup", "dup"),
	}
	_, err := Compose([]Source{packSource("team", pack, "")})
	if err == nil || !strings.Contains(err.Error(), "python/dup.yml") {
		t.Fatalf("error = %v, want the file with duplicate IDs named", err)
	}
}
