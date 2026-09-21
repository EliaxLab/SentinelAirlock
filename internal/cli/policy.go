package cli

import (
	"fmt"
	"os"

	"github.com/EliaxLab/SentinelAirlock/internal/policy"
	"github.com/EliaxLab/SentinelAirlock/internal/policypack"
	"github.com/spf13/cobra"
)

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Policy pack operations"}
	cmd.AddCommand(policyListCmd())
	cmd.AddCommand(policyShowCmd())
	cmd.AddCommand(policyApplyCmd())
	cmd.AddCommand(policyConfigureCmd())
	return cmd
}

func policyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available policy packs",
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, p := range policypack.List() {
				fmt.Printf("%s\t%s\t%s\n", p.Name, p.Version, p.Source)
			}
			return nil
		},
	}
}

func policyShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [pack]",
		Short: "Show effective project policy (no args) or a named policy pack YAML",
		Args:  cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				p, err := policypack.Get(args[0])
				if err != nil {
					return err
				}
				fmt.Println(p.YAML)
				return nil
			}
			return showEffectivePolicy()
		},
	}
}

func showEffectivePolicy() error {
	const policyPath = "airlock.yaml"
	cfg, err := policy.Load(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No project policy found.")
			fmt.Println("Run:")
			fmt.Println("  airlock init")
			return nil
		}
		return err
	}

	packName := cfg.Defaults.PolicyPack
	if packName != "" {
		if pack, packErr := policypack.Get(packName); packErr == nil {
			if packCfg, parseErr := policypack.ParseConfig(pack); parseErr == nil {
				cfg = policypack.Merge(cfg, packCfg)
			}
		}
	}

	network := cfg.Network.Mode
	if network == "" {
		network = "off"
	}
	sandbox := cfg.Defaults.Sandbox
	if sandbox == "" {
		sandbox = "workspace"
	}

	fmt.Printf("Policy source    %s\n", policyPath)
	if packName != "" {
		fmt.Printf("Policy pack      %s\n", packName)
	} else {
		fmt.Printf("Policy pack      (not configured)\n")
	}
	fmt.Printf("Network          %s\n", network)
	fmt.Printf("Sandbox          %s\n", sandbox)

	if len(cfg.Network.Allowlist) > 0 {
		fmt.Println("Network allowlist")
		for _, d := range cfg.Network.Allowlist {
			fmt.Printf("  %s\n", d)
		}
	} else {
		fmt.Println("Network allowlist none")
	}

	if len(cfg.Policy.AllowWrite) > 0 {
		fmt.Println("Allow rules")
		for _, r := range cfg.Policy.AllowWrite {
			fmt.Printf("  %s\n", r)
		}
	} else {
		fmt.Println("Allow rules      none (all writes allowed)")
	}

	if len(cfg.Policy.DenyWrite) > 0 {
		fmt.Println("Deny rules")
		for _, r := range cfg.Policy.DenyWrite {
			fmt.Printf("  %s\n", r)
		}
	} else {
		fmt.Println("Deny rules       none configured")
		fmt.Println()
		fmt.Println("No explicit path deny rules are configured.")
		fmt.Println("Files such as .env are not automatically blocked unless")
		fmt.Println("your effective policy defines a matching deny rule.")
		fmt.Println()
		fmt.Println("To configure deny rules, add to airlock.yaml:")
		fmt.Println("  policy:")
		fmt.Println("    deny_write:")
		fmt.Println("      - '**/.env'")
		fmt.Println("      - '**/*.key'")
		fmt.Println("      - '**/secrets/**'")
	}
	return nil
}

func policyApplyCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "apply <pack>",
		Short: "Apply policy pack to airlock.yaml",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := policypack.Get(args[0])
			if err != nil {
				return err
			}
			if out == "" {
				out = "airlock.yaml"
			}
			if err := os.WriteFile(out, []byte(p.YAML), 0o644); err != nil {
				return err
			}
			fmt.Printf("Applied policy pack %s to %s\n", p.Name, out)
			return nil
		},
	}
	c.Flags().StringVar(&out, "out", "airlock.yaml", "Policy output path")
	return c
}
