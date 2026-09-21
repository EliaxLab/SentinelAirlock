package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/agents"
	"github.com/EliaxLab/SentinelAirlock/internal/policy"
	"github.com/spf13/cobra"
)

func agentsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agents", Short: "Agent adapter readiness diagnostics"}
	cmd.AddCommand(agentsListCmd())
	cmd.AddCommand(agentsDoctorCmd())
	cmd.AddCommand(agentsInspectCmd())
	cmd.AddCommand(agentsInstallHintsCmd())
	cmd.AddCommand(agentsDefaultCmd())
	cmd.AddCommand(agentsUseCmd())
	return cmd
}

func agentsListCmd() *cobra.Command {
	return &cobra.Command{Use: "list", Short: "List known agents", RunE: func(cmd *cobra.Command, args []string) error {
		defaultAgent := ""
		if cfg, err := policy.Load("airlock.yaml"); err == nil {
			defaultAgent = strings.TrimSpace(cfg.Defaults.Agent)
		}
		for _, n := range agents.Known() {
			if n == defaultAgent {
				fmt.Printf("%s (default)\n", n)
				continue
			}
			fmt.Println(n)
		}
		return nil
	}}
}

func agentsDoctorCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{Use: "doctor", Short: "Diagnose all known agents", RunE: func(cmd *cobra.Command, args []string) error {
		infos := []agents.Info{}
		for _, n := range agents.Known() {
			infos = append(infos, agents.Diagnose(n))
		}
		if asJSON {
			b, _ := json.MarshalIndent(infos, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		for _, i := range infos {
			fmt.Printf("%-14s status=%-11s installed=%-5t", i.Name, i.Status, i.Installed)
			if i.Path != "" {
				fmt.Printf(" path=%s", i.Path)
			}
			if i.Version != "" {
				fmt.Printf(" version=%s", i.Version)
			}
			if i.Hint != "" {
				fmt.Printf("\n  hint: %s", i.Hint)
			}
			fmt.Println()
		}
		return nil
	}}
	c.Flags().BoolVar(&asJSON, "json", false, "JSON output")
	return c
}

func agentsInspectCmd() *cobra.Command {
	return &cobra.Command{Use: "inspect <agent>", Short: "Inspect one agent", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		i := agents.Diagnose(args[0])
		b, _ := json.MarshalIndent(i, "", "  ")
		fmt.Println(string(b))
		return nil
	}}
}

func agentsInstallHintsCmd() *cobra.Command {
	return &cobra.Command{Use: "install-hints", Short: "Show install hints for agent backends", RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("generic-shell: built-in, no install needed")
		fmt.Println("codex: install Codex CLI and ensure `codex` is in PATH")
		fmt.Println("claude-code: install Claude Code CLI and ensure `claude-code` is in PATH")
		fmt.Println("openclaw: install OpenClaw CLI and ensure `openclaw` is in PATH")
		fmt.Println("ollama: install Ollama and ensure `ollama` is in PATH")
		return nil
	}}
}

func agentsDefaultCmd() *cobra.Command {
	var policyPath string
	c := &cobra.Command{Use: "default <agent>", Short: "Set default agent in config", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := policy.Load(policyPath)
		if err != nil {
			return err
		}
		cfg.Defaults.Agent = strings.TrimSpace(args[0])
		if err := savePolicy(policyPath, cfg); err != nil {
			return err
		}
		fmt.Printf("Default agent set: %s (%s)\n", cfg.Defaults.Agent, policyPath)
		return nil
	}}
	c.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path")
	return c
}

func agentsUseCmd() *cobra.Command {
	var policyPath string
	c := &cobra.Command{Use: "use <agent>", Short: "Alias for agents default", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := policy.Load(policyPath)
		if err != nil {
			return err
		}
		cfg.Defaults.Agent = strings.TrimSpace(args[0])
		if err := savePolicy(policyPath, cfg); err != nil {
			return err
		}
		fmt.Printf("Default agent set: %s (%s)\n", cfg.Defaults.Agent, policyPath)
		return nil
	}}
	c.Flags().StringVar(&policyPath, "policy", "airlock.yaml", "Policy config path")
	return c
}
