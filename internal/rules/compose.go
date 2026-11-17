package rules

import (
	"bufio"
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/josh-billington/pug/internal/report"
	"github.com/josh-billington/pug/internal/tools"
)

//go:embed starter.yml
var starterFS embed.FS

const maxRulesFile = 16 << 20

// Source is a spec with the files it reads from.
type Source struct {
	Spec Spec
	// Files is the installed pack tree, or the directory holding File.
	Files fs.FS
	// File names the rules file within Files for starter and file specs.
	File string
	// Commit is the installed commit of a pack.
	Commit string
}

// Ruleset is one composed OpenGrep config and the provenance of its rules.
type Ruleset struct {
	Config     []byte
	Provenance report.RuleProvenance
}

// Resolve locates each spec's files. Packs whose pinned commit is not
// installed are returned in missing, once each, instead of as sources.
func Resolve(specs []Spec) (sources []Source, missing []string, err error) {
	home := ""
	for _, spec := range specs {
		switch spec.Kind {
		case StarterSpec:
			sources = append(sources, Source{Spec: spec, Files: starterFS, File: "starter.yml"})
		case FileSpec:
			absolute, err := filepath.Abs(spec.Path)
			if err != nil {
				return nil, nil, fmt.Errorf("resolve rules file: %w", err)
			}
			sources = append(sources, Source{Spec: spec, Files: os.DirFS(filepath.Dir(absolute)), File: filepath.Base(absolute)})
		case PackSpec:
			if home == "" {
				if home, err = tools.Home(); err != nil {
					return nil, nil, err
				}
			}
			if !Installed(home, spec.Pack) {
				if !slices.Contains(missing, spec.Pack.Name) {
					missing = append(missing, spec.Pack.Name)
				}
				continue
			}
			sources = append(sources, Source{Spec: spec, Files: os.DirFS(Dir(home, spec.Pack.Name)), Commit: spec.Pack.Commit})
		}
	}
	return sources, missing, nil
}

// Compose merges the sources' rules into one config. Pack rules get IDs
// qualified by pack and file path, so a rule keeps one ID whichever profile
// or spec selected it, and no two pack rules share an ID. Starter and file
// rules keep their own IDs. Rules are ordered by ID, so the config depends
// only on which rules were selected. Two different rules with one ID are an
// error; the same rule selected twice is kept once.
func Compose(sources []Source) (Ruleset, error) {
	c := composer{rules: map[string]*yaml.Node{}, origin: map[string]string{}}
	c.provenance.Specs = []string{}
	for _, source := range sources {
		spec := source.Spec.String()
		c.provenance.Specs = append(c.provenance.Specs, spec)
		if source.Spec.Kind != PackSpec {
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
		if c.provenance.Packs == nil {
			c.provenance.Packs = map[string]string{}
		}
		c.provenance.Packs[source.Spec.Pack.Name] = source.Commit
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
	pack := source.Spec.Pack
	files := map[string][]rule{}
	load := func(name string) ([]rule, error) {
		if rules, ok := files[name]; ok {
			return rules, nil
		}
		rules, err := readRules(source.Files, name)
		if err != nil {
			return nil, err
		}
		files[name] = rules
		return rules, nil
	}
	addFile := func(name string, keep func(string) bool) (bool, error) {
		rules, err := load(name)
		if err != nil {
			return false, err
		}
		found := false
		for _, r := range rules {
			if !keep(r.id) {
				continue
			}
			found = true
			id := qualify(pack.Name, name, r.id)
			mappingValue(r.node, "id").Value = id
			if err := c.add(id, r.node, spec); err != nil {
				return false, err
			}
		}
		return found, nil
	}
	profile := source.Spec.effectiveProfile()
	if profile == "" {
		for _, dir := range pack.RuleDirs {
			err := fs.WalkDir(source.Files, dir, func(name string, entry fs.DirEntry, err error) error {
				if errors.Is(err, fs.ErrNotExist) && name == dir {
					return fs.SkipDir
				}
				if err != nil || entry.IsDir() || (path.Ext(name) != ".yml" && path.Ext(name) != ".yaml") {
					return err
				}
				_, err = addFile(name, func(string) bool { return true })
				return err
			})
			if err != nil {
				return fmt.Errorf("rules %s: %w", spec, err)
			}
		}
		return nil
	}
	list, err := fs.ReadFile(source.Files, path.Join(pack.ProfilesDir, profile+".list"))
	if errors.Is(err, fs.ErrNotExist) {
		profiles, _ := fs.Glob(source.Files, path.Join(pack.ProfilesDir, "*.list"))
		for i, name := range profiles {
			profiles[i] = strings.TrimSuffix(path.Base(name), ".list")
		}
		return fmt.Errorf("rule pack %s has no profile %q; profiles: %s", pack.Name, profile, strings.Join(profiles, ", "))
	}
	if err != nil {
		return fmt.Errorf("rules %s: %w", spec, err)
	}
	lines := bufio.NewScanner(bytes.NewReader(list))
	for lines.Scan() {
		entry := strings.TrimSpace(lines.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		resolved, err := c.addEntry(entry, addFile)
		if err != nil {
			return fmt.Errorf("rules %s: %w", spec, err)
		}
		if !resolved {
			c.provenance.Unresolved = append(c.provenance.Unresolved, spec+" "+entry)
		}
	}
	return lines.Err()
}

// addEntry adds the rule a "path:id" profile entry names. Profiles list
// some files with the other of .yaml and .yml, so both are tried.
func (c *composer) addEntry(entry string, addFile func(string, func(string) bool) (bool, error)) (bool, error) {
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
	info, err := fs.Stat(files, name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRulesFile {
		return nil, fmt.Errorf("%s must be a regular file no larger than 16 MiB", name)
	}
	data, err := fs.ReadFile(files, name)
	if err != nil {
		return nil, err
	}
	rules, err := parseRules(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return rules, nil
}
