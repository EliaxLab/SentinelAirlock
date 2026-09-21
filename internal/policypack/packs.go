package policypack

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/EliaxLab/SentinelAirlock/internal/policy"
)

type Pack struct {
	Name    string
	Version string
	Source  string
	YAML    string
}

func builtins() map[string]Pack {
	mk := func(name, yamlStr string) Pack {
		return Pack{Name: name, Version: "1.0.0", Source: "builtin", YAML: yamlStr}
	}
	return map[string]Pack{
		"strict":         mk("strict", baseYAML("off", []string{}, []string{"src/**", "app/**"})),
		"balanced":       mk("balanced", baseYAML("allowlist", []string{"github.com", "api.openai.com"}, []string{"src/**", "app/**", "*.md"})),
		"oss-maintainer": mk("oss-maintainer", baseYAML("allowlist", []string{"github.com"}, []string{"src/**", "app/**", "README.md", "package.json", "pyproject.toml"})),
		"ci-safe":        mk("ci-safe", baseYAML("off", []string{}, []string{"src/**", "app/**", "tests/**", "go.mod", "go.sum", "package.json", "pyproject.toml"})),
		"research":       mk("research", baseYAML("on", []string{}, []string{"src/**", "app/**", "notebooks/**", "*.md"})),
	}
}

func baseYAML(networkMode string, allowlist, allowWrite []string) string {
	return fmt.Sprintf(`version: 1
workspace:
  ignore:
    - ".git/**"
    - ".airlock/**"
    - "node_modules/**"
policy:
  deny_read:
    - "**/.env"
    - "**/*.pem"
    - "**/.ssh/**"
    - "**/.aws/**"
  deny_write:
    - ".git/**"
    - ".airlock/**"
  allow_write:
%s
network:
  mode: %q
  allowlist:
%s
`, yamlList(allowWrite), networkMode, yamlList(allowlist))
}

func yamlList(in []string) string {
	if len(in) == 0 {
		return "    - \"\""
	}
	out := ""
	for _, s := range in {
		out += "    - \"" + s + "\"\n"
	}
	return strings.TrimRight(out, "\n")
}

func List() []Pack {
	merged := builtins()
	for k, v := range localPacks("airlock.presets") {
		merged[k] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Pack, 0, len(keys))
	for _, k := range keys {
		out = append(out, merged[k])
	}
	return out
}

func Get(name string) (Pack, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if p, ok := localPacks("airlock.presets")[name]; ok {
		return p, nil
	}
	if p, ok := builtins()[name]; ok {
		return p, nil
	}
	return Pack{}, fmt.Errorf("unknown policy pack %q", name)
}

func localPacks(root string) map[string]Pack {
	out := map[string]Pack{}
	ents, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
			continue
		}
		path := filepath.Join(root, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(e.Name()), ".yaml")
		p := Pack{Name: name, Version: "1.0.0", Source: path, YAML: string(b)}
		var meta struct {
			Name    string `yaml:"name"`
			Version string `yaml:"version"`
		}
		if err := yaml.Unmarshal(b, &meta); err == nil {
			if strings.TrimSpace(meta.Name) != "" {
				p.Name = strings.TrimSpace(meta.Name)
				name = strings.ToLower(p.Name)
			}
			if strings.TrimSpace(meta.Version) != "" {
				p.Version = strings.TrimSpace(meta.Version)
			}
		}
		out[name] = p
	}
	return out
}

func ParseConfig(p Pack) (*policy.Config, error) {
	var cfg policy.Config
	if err := yaml.Unmarshal([]byte(p.YAML), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Merge applies pack defaults into base, but base config takes precedence:
// if base already has a non-empty value for a field, the pack does not override it.
// This ensures a custom --policy file wins over a built-in policy pack.
func Merge(base *policy.Config, pack *policy.Config) *policy.Config {
	if base == nil {
		cp := *pack
		return &cp
	}
	out := *base
	if len(pack.Workspace.Ignore) > 0 && len(out.Workspace.Ignore) == 0 {
		out.Workspace.Ignore = append([]string(nil), pack.Workspace.Ignore...)
	}
	if len(pack.Policy.DenyRead) > 0 && len(out.Policy.DenyRead) == 0 {
		out.Policy.DenyRead = append([]string(nil), pack.Policy.DenyRead...)
	}
	if len(pack.Policy.DenyWrite) > 0 && len(out.Policy.DenyWrite) == 0 {
		out.Policy.DenyWrite = append([]string(nil), pack.Policy.DenyWrite...)
	}
	if len(pack.Policy.AllowWrite) > 0 && len(out.Policy.AllowWrite) == 0 {
		out.Policy.AllowWrite = append([]string(nil), pack.Policy.AllowWrite...)
	}
	if pack.Network.Mode != "" && out.Network.Mode == "" {
		out.Network.Mode = pack.Network.Mode
	}
	if len(pack.Network.Allowlist) > 0 && len(out.Network.Allowlist) == 0 {
		out.Network.Allowlist = append([]string(nil), pack.Network.Allowlist...)
	}
	return &out
}
