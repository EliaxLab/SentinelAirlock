package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/EliaxLab/SentinelAirlock/internal/index"
	"github.com/spf13/cobra"
)

func indexCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "index", Short: "Run index operations"}
	cmd.AddCommand(indexRebuildCmd())
	cmd.AddCommand(indexStatsCmd())
	return cmd
}

func indexRebuildCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rebuild",
		Short: "Rebuild local run index",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := index.Rebuild(filepath.Join(".airlock", "runs"))
			if err != nil {
				return err
			}
			if err := index.Save(index.DefaultPath(), store); err != nil {
				return err
			}
			fmt.Printf("indexed %d runs at %s\n", len(store.Runs), index.DefaultPath())
			return nil
		},
	}
}

func indexStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show index stats",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := index.Load(index.DefaultPath())
			if err != nil {
				return err
			}
			payload := map[string]any{"updated": store.Updated, "count": len(store.Runs)}
			b, _ := json.MarshalIndent(payload, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}
}
