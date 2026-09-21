package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/EliaxLab/SentinelAirlock/internal/util"
	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize airlock.yaml and .airlock directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				out = "airlock.yaml"
			}

			if err := os.MkdirAll(".airlock", 0o755); err != nil {
				return err
			}

			if util.FileExists(out) {
				return fmt.Errorf("%s already exists", out)
			}

			defaultCfg := `version: 1
# Sentinel Airlock config
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
    - "src/**"
    - "app/**"
network:
  mode: "off"   # off | on | allowlist
  allowlist: []
team:
  name: ""
  default_worker: ""
  index_path: ".airlock/index.json"
defaults:
  agent: "generic-shell"
  mode: "dev"
  policy_pack: "balanced"
  sandbox: "workspace"
signing:
  private_key: "" # optional path to ed25519 key
  public_key: ""  # optional path to ed25519 pubkey
  key_id: ""
`
			if err := os.WriteFile(out, []byte(defaultCfg), 0o644); err != nil {
				return err
			}
			if !util.FileExists(".airlockignore") {
				ignore := ".airlock/**\n.git/**\nnode_modules/**\n"
				if err := os.WriteFile(".airlockignore", []byte(ignore), 0o644); err != nil {
					return err
				}
			}
			if err := os.MkdirAll("airlock.presets", 0o755); err != nil {
				return err
			}
			defaultPreset := `name: strict
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
    - "src/**"
    - "app/**"
network:
  mode: "off"
  allowlist: []
`
			presetPath := filepath.Join("airlock.presets", "strict.yaml")
			if !util.FileExists(presetPath) {
				if err := os.WriteFile(presetPath, []byte(defaultPreset), 0o644); err != nil {
					return err
				}
			}

			abs, _ := filepath.Abs(out)
			fmt.Printf("Initialized:\n- %s\n- %s\n- %s\n- %s\n",
				abs, filepath.Join(".airlock"), ".airlockignore", filepath.Join("airlock.presets", "strict.yaml"))
			return nil
		},
	}

	cmd.Flags().StringVarP(&out, "out", "o", "airlock.yaml", "Output config path")
	return cmd
}
