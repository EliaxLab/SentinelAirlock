package cli

import (
	"bufio"
	"fmt"
	"os"

	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

func patchCmd() *cobra.Command {
	var (
		show  bool
		stats bool
	)
	cmd := &cobra.Command{
		Use:   "patch <run_id>",
		Short: "Inspect patch artifact for a run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runID := args[0]
			a, err := runmeta.LoadArtifacts(runID)
			if err != nil {
				return err
			}
			fmt.Printf("Patch path: %s\n", a.PatchPath)
			if !runmeta.Exists(a.PatchPath) {
				fmt.Println("Exists: no")
				return nil
			}
			fmt.Println("Exists: yes")
			info, err := os.Stat(a.PatchPath)
			if err != nil {
				return err
			}
			fmt.Printf("Size: %d bytes\n", info.Size())
			if stats {
				fmt.Printf("Lines: %d\n", countLines(a.PatchPath))
			}
			if show {
				f, err := os.Open(a.PatchPath)
				if err != nil {
					return err
				}
				defer f.Close()
				sc := bufio.NewScanner(f)
				n := 0
				for sc.Scan() {
					fmt.Println(sc.Text())
					n++
					if n >= 40 {
						break
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&show, "show", false, "Show first lines of patch")
	cmd.Flags().BoolVar(&stats, "stats", false, "Show patch stats")
	return cmd
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
	}
	return n
}
