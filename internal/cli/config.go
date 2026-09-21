package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/execution"
	"github.com/EliaxLab/SentinelAirlock/internal/governance"
	"github.com/EliaxLab/SentinelAirlock/internal/policy"
	"github.com/EliaxLab/SentinelAirlock/internal/policypack"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Config tools"}
	cmd.AddCommand(configResolveCmd())
	cmd.AddCommand(configGetCmd())
	cmd.AddCommand(configSetCmd())
	cmd.AddCommand(configDoctorCmd())
	return cmd
}

func configResolveCmd() *cobra.Command {
	var (
		policyPath  string
		policyPack  string
		mode        string
		sandbox     string
		network     string
		approval    string
		allowEnv    string
		allowDomain []string
	)
	c := &cobra.Command{Use: "resolve", Short: "Show effective merged config", RunE: func(cmd *cobra.Command, args []string) error {
		policyPath = configDefaultString(policyPath, "airlock.yaml")
		mode = configDefaultString(mode, "dev")
		sandbox = configDefaultString(sandbox, string(execution.ModeWorkspace))
		network = configDefaultString(network, string(execution.NetworkOff))
		approval = configDefaultString(approval, string(governance.ApprovalAuto))
		cfg, _ := policy.Load(policyPath)
		if p, err := resolvePolicyPack(policyPack, mode, cmd.Flags().Changed("policy-pack")); err == nil && p != nil {
			pcfg, err := policypack.ParseConfig(*p)
			if err != nil {
				return err
			}
			cfg = policypack.Merge(cfg, pcfg)
			policyPack = p.Name
		}
		applyModeDefaults(cmd.Flags(), mode, &sandbox, &network, &approval)
		if cfg != nil && network == string(execution.NetworkOff) && cfg.Network.Mode != "" {
			network = cfg.Network.Mode
		}
		out := map[string]any{
			"policy_path":   policyPath,
			"policy_pack":   policyPack,
			"mode":          mode,
			"approval":      approval,
			"sandbox":       sandbox,
			"network":       network,
			"allow_env":     parseCSV(allowEnv),
			"allow_domains": allowDomain,
		}
		if cfg != nil {
			out["policy"] = cfg
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}}
	c.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path")
	c.Flags().StringVar(&policyPack, "policy-pack", "", "Policy pack")
	c.Flags().StringVar(&mode, "mode", "dev", "Execution mode")
	c.Flags().StringVar(&sandbox, "sandbox", string(execution.ModeWorkspace), "Sandbox mode")
	c.Flags().StringVar(&network, "network", string(execution.NetworkOff), "Network mode")
	c.Flags().StringVar(&approval, "approval", string(governance.ApprovalAuto), "Approval mode")
	c.Flags().StringVar(&allowEnv, "allow-env", "", "Env allowlist CSV")
	c.Flags().StringSliceVar(&allowDomain, "allow-domain", nil, "Allowed domain")
	return c
}

func configDefaultString(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

func configGetCmd() *cobra.Command {
	var path string
	c := &cobra.Command{Use: "get", Short: "Show current config and defaults", RunE: func(cmd *cobra.Command, args []string) error {
		path = configDefaultString(path, "airlock.yaml")
		cfg, err := policy.Load(path)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(map[string]any{"path": path, "defaults": cfg.Defaults, "team": cfg.Team}, "", "  ")
		fmt.Println(string(b))
		return nil
	}}
	c.Flags().StringVar(&path, "policy", "airlock.yaml", "Policy config path")
	return c
}

func configSetCmd() *cobra.Command {
	var path string
	c := &cobra.Command{Use: "set <key> <value>", Short: "Set common config values", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		path = configDefaultString(path, "airlock.yaml")
		cfg, err := policy.Load(path)
		if err != nil {
			return err
		}
		key, val := strings.TrimSpace(args[0]), strings.TrimSpace(args[1])
		switch key {
		case "default_agent":
			cfg.Defaults.Agent = val
		case "default_mode":
			cfg.Defaults.Mode = val
		case "default_policy_pack":
			cfg.Defaults.PolicyPack = val
		case "default_sandbox":
			cfg.Defaults.Sandbox = val
		default:
			return fmt.Errorf("unsupported key %q", key)
		}
		return savePolicy(path, cfg)
	}}
	c.Flags().StringVar(&path, "policy", "airlock.yaml", "Policy config path")
	return c
}

func configDoctorCmd() *cobra.Command {
	var path string
	c := &cobra.Command{Use: "doctor", Short: "Check config validity and defaults", RunE: func(cmd *cobra.Command, args []string) error {
		path = configDefaultString(path, "airlock.yaml")
		cfg, err := policy.Load(path)
		if err != nil {
			return err
		}
		fmt.Printf("config path: %s\n", path)
		fmt.Printf("default agent: %s\n", cfg.Defaults.Agent)
		fmt.Printf("default mode: %s\n", cfg.Defaults.Mode)
		fmt.Printf("default policy pack: %s\n", cfg.Defaults.PolicyPack)
		fmt.Printf("default sandbox: %s\n", cfg.Defaults.Sandbox)
		return nil
	}}
	c.Flags().StringVar(&path, "policy", "airlock.yaml", "Policy config path")
	return c
}

func savePolicy(path string, cfg *policy.Config) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("updated %s\n", path)
	return nil
}
