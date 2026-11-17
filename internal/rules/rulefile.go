package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"

	"go.yaml.in/yaml/v3"
)

var errNotRules = errors.New("not an OpenGrep rules file")

type rule struct {
	id   string
	node *yaml.Node
}

func parseRules(data []byte) ([]rule, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := decoder.Decode(&doc); err != nil {
		if rulesKey.Match(data) {
			return nil, fmt.Errorf("invalid rules YAML: %v", err)
		}
		return nil, fmt.Errorf("%w: %v", errNotRules, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: top level is not a mapping", errNotRules)
	}
	budget := maxExpandedNodes
	expanded, err := expandAliases(doc.Content[0], &budget)
	if err != nil {
		return nil, err
	}
	sequence := mappingValue(expanded, "rules")
	if sequence == nil || sequence.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%w: no top-level rules list", errNotRules)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("rules file has more than one YAML document")
	}
	rules := make([]rule, 0, len(sequence.Content))
	seen := map[string]bool{}
	for i, node := range sequence.Content {
		id := mappingValue(node, "id")
		if node.Kind != yaml.MappingNode || id == nil || id.Kind != yaml.ScalarNode || id.Value == "" {
			return nil, fmt.Errorf("rule %d has no id", i+1)
		}
		if seen[id.Value] {
			return nil, fmt.Errorf("duplicate rule id %q", id.Value)
		}
		seen[id.Value] = true
		rules = append(rules, rule{id: id.Value, node: node})
	}
	return rules, nil
}

const maxExpandedNodes = 1 << 20

var rulesKey = regexp.MustCompile(`(?m)^rules:`)

func expandAliases(node *yaml.Node, budget *int) (*yaml.Node, error) {
	*budget--
	if *budget < 0 {
		return nil, fmt.Errorf("YAML aliases expand beyond %d nodes", maxExpandedNodes)
	}
	if node.Kind == yaml.AliasNode {
		if node.Alias == nil {
			return nil, fmt.Errorf("YAML alias %q has no anchor", node.Value)
		}
		return expandAliases(node.Alias, budget)
	}
	copied := *node
	copied.Anchor = ""
	copied.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		var err error
		if copied.Content[i], err = expandAliases(child, budget); err != nil {
			return nil, err
		}
	}
	return &copied, nil
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
