package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/EliaxLab/SentinelAirlock/internal/policy"
	"github.com/spf13/cobra"
)

// presetDenyPaths are the common sensitive paths offered during interactive setup.
var presetDenyPaths = []string{
	"**/.env",
	"**/.env.*",
	"**/*.key",
	"**/*.pem",
	"**/secrets/**",
	"**/credentials/**",
}

func policyConfigureCmd() *cobra.Command {
	var policyPath string
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Interactively configure common policy settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyConfigure(policyPath, os.Stdin, os.Stdout, isStdinTerminal())
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path")
	return cmd
}

// isStdinTerminal reports whether os.Stdin is an interactive terminal.
func isStdinTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// runPolicyConfigure drives the interactive policy setup flow.
// interactive=false causes an immediate clean error (for pipes/CI).
// Accepts io.Reader/io.Writer so tests can drive it without a real terminal.
func runPolicyConfigure(policyPath string, in io.Reader, out io.Writer, interactive bool) error {
	if !interactive {
		fmt.Fprintln(out, "Interactive policy configuration requires a terminal.")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "You can instead edit airlock.yaml directly or run:")
		fmt.Fprintln(out, "  airlock policy show")
		return fmt.Errorf("not an interactive terminal")
	}

	fmt.Fprintln(out, "Sentinel Airlock — interactive policy setup")
	fmt.Fprintln(out, "")

	cfg, err := policy.Load(policyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("could not load %s: %w\nFix the YAML error before running configure", policyPath, err)
		}
		cfg = &policy.Config{}
		fmt.Fprintf(out, "Policy file: %s (will be created)\n\n", policyPath)
	} else {
		fmt.Fprintf(out, "Policy file: %s\n", policyPath)
		if len(cfg.Policy.DenyWrite) > 0 {
			fmt.Fprintln(out, "Current deny rules:")
			for _, r := range cfg.Policy.DenyWrite {
				fmt.Fprintf(out, "  %s\n", r)
			}
		} else {
			fmt.Fprintln(out, "Current deny rules: none configured")
		}
		fmt.Fprintln(out, "")
	}

	sc := bufio.NewScanner(in)

	// === Sensitive path protection ===
	fmt.Fprintln(out, "=== Sensitive path protection ===")
	var toAdd []string
	for _, path := range presetDenyPaths {
		if containsRule(cfg.Policy.DenyWrite, path) {
			fmt.Fprintf(out, "  %-28s already configured\n", path)
			continue
		}
		fmt.Fprintf(out, "Add deny rule for %q? [Y/n]: ", path)
		if yesOrDefault(readLine(sc)) {
			toAdd = append(toAdd, path)
		}
	}
	fmt.Fprint(out, "Custom path (leave blank to skip): ")
	if custom := strings.TrimSpace(readLine(sc)); custom != "" && !containsRule(cfg.Policy.DenyWrite, custom) {
		toAdd = append(toAdd, custom)
	}
	fmt.Fprintln(out, "")

	// === Network mode ===
	fmt.Fprintln(out, "=== Network mode ===")
	currentNetwork := cfg.Network.Mode
	if currentNetwork == "" {
		currentNetwork = "off"
	}
	fmt.Fprintf(out, "Current: %s\n", currentNetwork)
	fmt.Fprintln(out, "  1. off           (recommended — no outbound network)")
	fmt.Fprintln(out, "  2. allowlist     (only specified domains allowed)")
	fmt.Fprintln(out, "  3. unrestricted  (all outbound allowed)")
	fmt.Fprint(out, "Choice [1]: ")
	newNetwork := currentNetwork
	switch strings.TrimSpace(readLine(sc)) {
	case "2":
		newNetwork = "allowlist"
	case "3":
		newNetwork = "on"
	default:
		newNetwork = "off"
	}
	fmt.Fprintln(out, "")

	// Early exit if nothing would change.
	networkChanged := newNetwork != currentNetwork
	if len(toAdd) == 0 && !networkChanged {
		fmt.Fprintln(out, "No changes to apply.")
		return nil
	}

	// === Review ===
	fmt.Fprintln(out, "=== Changes to apply ===")
	if len(toAdd) > 0 {
		fmt.Fprintf(out, "Deny rules to add: %s\n", strings.Join(toAdd, ", "))
	}
	if networkChanged {
		fmt.Fprintf(out, "Network: %s → %s\n", currentNetwork, newNetwork)
	} else {
		fmt.Fprintf(out, "Network: %s (unchanged)\n", currentNetwork)
	}
	fmt.Fprintln(out, "")

	fmt.Fprint(out, "Apply these changes to airlock.yaml? [Y/n]: ")
	if !yesOrDefault(readLine(sc)) {
		fmt.Fprintln(out, "Cancelled. No changes written.")
		return nil
	}

	applyPolicyChanges(cfg, toAdd, newNetwork)
	if err := writeConfig(policyPath, cfg); err != nil {
		return fmt.Errorf("could not write %s: %w", policyPath, err)
	}

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Policy updated.")
	fmt.Fprintln(out, "Run:")
	fmt.Fprintln(out, "  airlock policy show")
	return nil
}

// applyPolicyChanges merges toAdd rules and newNetwork into cfg in place.
// Duplicate rules are silently skipped.
func applyPolicyChanges(cfg *policy.Config, toAdd []string, newNetwork string) {
	for _, rule := range toAdd {
		if !containsRule(cfg.Policy.DenyWrite, rule) {
			cfg.Policy.DenyWrite = append(cfg.Policy.DenyWrite, rule)
		}
	}
	if newNetwork != "" {
		cfg.Network.Mode = newNetwork
	}
}

// writeConfig marshals cfg back to YAML and writes it to path.
// Limitation: inline YAML comments in the original file are not preserved —
// all configured values survive the round-trip through the struct.
func writeConfig(path string, cfg *policy.Config) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	_ = enc.Close()
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// containsRule reports whether rules contains target (exact, case-sensitive).
func containsRule(rules []string, target string) bool {
	for _, r := range rules {
		if r == target {
			return true
		}
	}
	return false
}

// readLine reads one trimmed line from sc, returning "" on EOF or error.
func readLine(sc *bufio.Scanner) string {
	if sc.Scan() {
		return sc.Text()
	}
	return ""
}

// yesOrDefault returns true for blank input (default yes), "y", or "yes".
func yesOrDefault(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "" || s == "y" || s == "yes"
}
