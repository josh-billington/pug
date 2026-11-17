package rules

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/runner"
	"github.com/josh-billington/pug/internal/tools"
)

//go:embed starter.yml
var starterFS embed.FS

const maxRulesFile = 16 << 20

type Source struct {
	Spec      Spec
	Files     fs.FS
	File      string
	Name      string
	Directory string
	Commit    string
}

type Ruleset struct {
	Config     []byte
	Provenance report.RuleProvenance
}

func Resolve(specs []Spec) ([]Source, []string, error) {
	sources := []Source{}
	missing := []string{}
	home := ""
	for _, spec := range specs {
		switch spec.Kind {
		case StarterSpec:
			sources = append(sources, Source{Spec: spec, Files: starterFS, File: "starter.yml"})
		case PathSpec:
			absolute, err := filepath.Abs(spec.Path)
			if err != nil {
				return nil, nil, fmt.Errorf("resolve rules path: %w", err)
			}
			info, err := os.Stat(absolute)
			if err != nil {
				return nil, nil, fmt.Errorf("inspect rules path: %w", err)
			}
			if !info.IsDir() {
				if spec.Profile != "" {
					return nil, nil, fmt.Errorf("rules profiles require a directory")
				}
				sources = append(sources, Source{Spec: spec, Files: os.DirFS(filepath.Dir(absolute)), File: filepath.Base(absolute)})
				continue
			}
			source, err := directorySource(spec, filepath.Base(absolute), absolute)
			if err != nil {
				return nil, nil, err
			}
			sources = append(sources, source)
		case PackSpec:
			if home == "" {
				var err error
				home, err = tools.Home()
				if err != nil {
					return nil, nil, err
				}
			}
			dir := Dir(home, spec.Name)
			info, err := os.Stat(dir)
			if errors.Is(err, fs.ErrNotExist) {
				if !slices.Contains(missing, spec.Name) {
					missing = append(missing, spec.Name)
				}
				continue
			}
			if err != nil {
				return nil, nil, fmt.Errorf("inspect rule pack: %w", err)
			}
			if !info.IsDir() {
				return nil, nil, fmt.Errorf("rule pack %s must be a directory", spec.Name)
			}
			source, err := directorySource(spec, spec.Name, dir)
			if err != nil {
				return nil, nil, err
			}
			sources = append(sources, source)
		}
	}
	return sources, missing, nil
}

func directorySource(spec Spec, name, dir string) (Source, error) {
	commit, err := Commit(context.Background(), runner.Local{}, dir)
	if err != nil {
		return Source{}, err
	}
	return Source{Spec: spec, Name: name, Directory: dir, Commit: commit}, nil
}

func Compose(sources []Source) (Ruleset, error) {
	c := composer{rules: map[string]*yaml.Node{}, origin: map[string]string{}}
	c.provenance.Specs = []string{}
	for _, source := range sources {
		spec := source.Spec.String()
		c.provenance.Specs = append(c.provenance.Specs, spec)
		if source.File != "" {
			rules, err := readRules(source.Files, source.File)
			if err != nil {
				return Ruleset{}, fmt.Errorf("rules %s: %w", spec, err)
			}
			for _, r := range rules {
				if err := c.add(r.id, r.node, spec); err != nil {
					return Ruleset{}, err
				}
			}
			continue
		}
		if source.Commit != "" {
			if c.provenance.Packs == nil {
				c.provenance.Packs = map[string]string{}
			}
			c.provenance.Packs[source.Name] = source.Commit
		}
		if err := c.addPack(source, spec); err != nil {
			return Ruleset{}, err
		}
	}
	if len(c.rules) == 0 {
		return Ruleset{}, fmt.Errorf("the selected rules contain no rules")
	}
	ids := make([]string, 0, len(c.rules))
	for id := range c.rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	sequence := &yaml.Node{Kind: yaml.SequenceNode}
	for _, id := range ids {
		sequence.Content = append(sequence.Content, c.rules[id])
	}
	var config bytes.Buffer
	encoder := yaml.NewEncoder(&config)
	encoder.SetIndent(2)
	err := encoder.Encode(&yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: "rules"}, sequence}})
	if err == nil {
		err = encoder.Close()
	}
	if err != nil {
		return Ruleset{}, fmt.Errorf("encode composed rules: %w", err)
	}
	c.provenance.Rules = len(ids)
	c.provenance.SHA256 = report.Digest(config.Bytes())
	return Ruleset{Config: config.Bytes(), Provenance: c.provenance}, nil
}

type composer struct {
	rules      map[string]*yaml.Node
	origin     map[string]string
	provenance report.RuleProvenance
}

func (c *composer) add(id string, node *yaml.Node, spec string) error {
	if existing, ok := c.rules[id]; ok {
		if existing == node || sameRule(existing, node) {
			return nil
		}
		return fmt.Errorf("rule id %q from %s conflicts with a different rule from %s", id, spec, c.origin[id])
	}
	c.rules[id], c.origin[id] = node, spec
	return nil
}

func sameRule(a, b *yaml.Node) bool {
	left, err := yaml.Marshal(a)
	if err != nil {
		return false
	}
	right, err := yaml.Marshal(b)
	return err == nil && bytes.Equal(left, right)
}

func (c *composer) addPack(source Source, spec string) error {
	if source.Directory != "" {
		root, err := os.OpenRoot(source.Directory)
		if err != nil {
			return fmt.Errorf("open rule pack: %w", err)
		}
		defer root.Close()
		source.Files = root.FS()
	}
	allowed := map[string]bool{}
	err := fs.WalkDir(source.Files, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name != "." && strings.HasPrefix(entry.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		ext := path.Ext(name)
		fixture := strings.HasSuffix(name, ".test.yml") || strings.HasSuffix(name, ".test.yaml") || strings.Contains(entry.Name(), ".fixed.")
		if (ext == ".yml" || ext == ".yaml") && !fixture {
			allowed[name] = true
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("rules %s: %w", spec, err)
	}
	files := map[string][]rule{}
	addFile := func(name string, keep func(string) bool) (bool, error) {
		if !allowed[name] {
			return false, fs.ErrNotExist
		}
		rules, ok := files[name]
		if !ok {
			var err error
			rules, err = readRules(source.Files, name)
			if errors.Is(err, errNotRules) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			for _, r := range rules {
				mappingValue(r.node, "id").Value = qualify(source.Name, name, r.id)
			}
			files[name] = rules
		}
		found := false
		for _, r := range rules {
			if !keep(r.id) {
				continue
			}
			found = true
			if err := c.add(qualify(source.Name, name, r.id), r.node, spec); err != nil {
				return false, err
			}
		}
		return found, nil
	}
	profiles, err := profileNames(source.Files)
	if err != nil {
		return err
	}
	profile := source.Spec.Profile
	if profile == "" && slices.Contains(profiles, "default") {
		profile = "default"
	}
	if profile == "" {
		names := make([]string, 0, len(allowed))
		for name := range allowed {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			if _, err := addFile(name, func(string) bool { return true }); err != nil {
				return fmt.Errorf("rules %s: %w", spec, err)
			}
		}
		return nil
	}
	if !slices.Contains(profiles, profile) {
		return fmt.Errorf("rule pack %s has no profile %q; profiles: %s", source.Name, profile, strings.Join(profiles, ", "))
	}
	list, err := readFile(source.Files, path.Join("configs", profile+".list"))
	if err != nil {
		return fmt.Errorf("rules %s: %w", spec, err)
	}
	lines := bufio.NewScanner(bytes.NewReader(list))
	for lines.Scan() {
		entry := strings.TrimSpace(lines.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		resolved, err := addEntry(entry, addFile)
		if err != nil {
			return fmt.Errorf("rules %s: %w", spec, err)
		}
		if !resolved {
			c.provenance.Unresolved = append(c.provenance.Unresolved, spec+" "+entry)
		}
	}
	if err := lines.Err(); err != nil {
		return fmt.Errorf("read rules profile %s: %w", spec, err)
	}
	return nil
}

// addEntry adds the rule a "path:id" profile entry names. Profiles list
// some files with the other of .yaml and .yml, so both are tried.
func addEntry(entry string, addFile func(string, func(string) bool) (bool, error)) (bool, error) {
	i := strings.LastIndex(entry, ":")
	if i <= 0 {
		return false, nil
	}
	name, id := entry[:i], entry[i+1:]
	stem := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
	for _, candidate := range []string{name, stem + ".yaml", stem + ".yml"} {
		if !fs.ValidPath(candidate) {
			return false, nil
		}
		found, err := addFile(candidate, func(ruleID string) bool { return ruleID == id })
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return found, err
	}
	return false, nil
}

func qualify(pack, name, id string) string {
	stem := strings.TrimSuffix(name, path.Ext(name))
	qualified := pack + "." + strings.ReplaceAll(stem, "/", ".")
	if id != path.Base(stem) {
		qualified += "." + id
	}
	return qualified
}

func readRules(files fs.FS, name string) ([]rule, error) {
	data, err := readFile(files, name)
	if err != nil {
		return nil, err
	}
	rules, err := parseRules(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return rules, nil
}

func readFile(files fs.FS, name string) ([]byte, error) {
	info, err := fs.Stat(files, name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRulesFile {
		return nil, fmt.Errorf("%s must be a regular file no larger than 16 MiB", name)
	}
	file, err := files.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxRulesFile+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, err
	}
	if len(data) > maxRulesFile {
		return nil, fmt.Errorf("%s exceeds 16 MiB", name)
	}
	return data, nil
}

func profileNames(files fs.FS) ([]string, error) {
	profiles := []string{}
	info, err := fs.Lstat(files, "configs")
	if errors.Is(err, fs.ErrNotExist) || err == nil && !info.IsDir() {
		return profiles, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read rule profiles: %w", err)
	}
	matches, err := fs.Glob(files, "configs/*.list")
	if err != nil {
		return nil, fmt.Errorf("read rule profiles: %w", err)
	}
	for _, match := range matches {
		info, err := fs.Lstat(files, match)
		if err != nil {
			return nil, fmt.Errorf("read rule profiles: %w", err)
		}
		if name := strings.TrimSuffix(path.Base(match), ".list"); info.Mode().IsRegular() && profileName.MatchString(name) {
			profiles = append(profiles, name)
		}
	}
	return profiles, nil
}
