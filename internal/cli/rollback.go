package cli

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/rollback"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

func rollbackCmd() *cobra.Command {
	var (
		// --run is kept for backward compat (web server, old scripts).
		runFlag     string
		checkpoint  string
		dryRun      bool
		force       bool
		restorePath string
	)

	cmd := &cobra.Command{
		Use:   "rollback [run_id]",
		Short: "Restore a run workspace from a saved checkpoint",
		Long: `Restores a run's execution root from its checkpoint.

For workspace/container runs, this restores .airlock/workspaces/<run_id>/repo
— NOT your original source directory. Your working repo is untouched.

For sandbox=off (in-place) runs, the agent ran directly against your real
--repo, so restore means reverting exactly the paths that run touched or
attempted to touch back to their pre-run state. Files outside that set
(.git, node_modules, unrelated work) are never modified — there is no
whole-directory wipe of your real repo.

Modes:
  Full restore:      airlock rollback <run_id>
  Subtree restore:   airlock rollback <run_id> --path src/slides/final
  Preview only:      airlock rollback <run_id> --dry-run
  Skip confirmation: airlock rollback <run_id> --force

After rollback:
  - run_digest.json is rebuilt so 'airlock verify' stays consistent.
  - review.json is set to 'needs-attention' so a prior approved decision
    is not silently left in place.
  - rollback.json is written as a permanent rollback artifact.
  - report/index.html is regenerated.

Limitations:
  - Restores only what this run touched or attempted to touch. Changes made
    outside of an Airlock run (in-place or otherwise) are never affected.
  - One checkpoint per run (cp-0), taken before agent execution.
  - Operation-level rollback (undo last N moves) is future work.
  - Patch-reverse is not supported in this release.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Positional arg takes priority; --run is backward compat.
			rawID := runFlag
			if len(args) > 0 {
				rawID = args[0]
			}
			if rawID == "" {
				return fmt.Errorf("run ID required: airlock rollback <run_id> or airlock rollback latest")
			}

			runID, err := runmeta.ResolveRunID(rawID)
			if err != nil {
				return err
			}
			if checkpoint == "" {
				checkpoint = "cp-0"
			}

			opts := rollback.Options{RunID: runID, Checkpoint: checkpoint, Path: restorePath}

			// Resolve/validate the target up front (shared with dry-run preview).
			plan, err := rollback.BuildPlan(opts)
			if err != nil {
				return err
			}

			// --- dry-run -------------------------------------------------------
			if dryRun {
				return doDryRun(plan)
			}

			// --- confirmation --------------------------------------------------
			if !force {
				if err := confirmPrompt(plan); err != nil {
					return err
				}
			}

			// --- restore (shared rollback service) -----------------------------
			res, err := rollback.Execute(opts)
			if err != nil {
				return err
			}

			// --- summary ------------------------------------------------------
			fmt.Printf("Rollback complete.\n")
			fmt.Printf("  Run ID:     %s\n", res.RunID)
			fmt.Printf("  Checkpoint: %s\n", res.Checkpoint)
			fmt.Printf("  Mode:       %s\n", res.Mode)
			if plan.Path != "" {
				fmt.Printf("  Path:       %s\n", plan.Path)
			}
			if res.InPlace {
				fmt.Printf("  Execution:  in-place\n")
				fmt.Printf("  Repo:       %s\n", res.WorkspacePath)
				fmt.Printf("  Restored:   %d touched path(s)\n", len(res.Paths))
			} else {
				fmt.Printf("  Workspace:  %s\n", res.WorkspacePath)
			}
			fmt.Printf("  Review:     needs-attention (re-review required)\n")
			fmt.Printf("  Report:     %s\n", filepath.Join(".airlock", "runs", res.RunID, "report", "index.html"))
			if res.DigestRebuilt {
				fmt.Printf("  Digest:     rebuilt\n")
			}
			return nil
		},
	}

	// --run is hidden: kept for backward compat with web server and old scripts.
	cmd.Flags().StringVar(&runFlag, "run", "", "Run ID to restore (use positional arg instead)")
	_ = cmd.Flags().MarkHidden("run")
	cmd.Flags().StringVar(&checkpoint, "checkpoint", "cp-0", "Checkpoint ID to restore")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be restored without modifying anything")
	cmd.Flags().BoolVar(&force, "force", false, "Skip confirmation prompt (for scripts and web)")
	cmd.Flags().StringVar(&restorePath, "path", "", "Restore only this repo-relative path/subtree from checkpoint")
	return cmd
}

// --- dry-run ----------------------------------------------------------------

func doDryRun(plan rollback.Plan) error {
	fmt.Printf("Dry-run: no files will be modified.\n\n")
	fmt.Printf("  Run ID:     %s\n", plan.RunID)
	fmt.Printf("  Checkpoint: %s\n  Source:     %s\n", plan.Checkpoint, plan.CheckpointPath)
	if plan.InPlace {
		fmt.Printf("  Execution:  in-place\n  Repo:       %s\n", plan.WorkspacePath)
	} else {
		fmt.Printf("  Workspace:  %s\n", plan.WorkspacePath)
	}

	if plan.Path != "" {
		cpSub := filepath.Join(plan.CheckpointPath, plan.Path)
		wsSub := filepath.Join(plan.WorkspacePath, plan.Path)
		fmt.Printf("  Mode:       path\n")
		fmt.Printf("  Path:       %s\n", plan.Path)
		fmt.Printf("\n  Checkpoint source: %s  (exists=%v)\n", cpSub, fsExists(cpSub))
		fmt.Printf("  Target:            %s  (exists=%v)\n", wsSub, fsExists(wsSub))
		if fsExists(cpSub) {
			fc, dc := countFS(cpSub)
			fmt.Printf("  Would restore: %d file(s) in %d dir(s)\n", fc, dc)
		} else {
			fmt.Printf("  Note: path not in checkpoint — would be removed from target.\n")
		}
	} else if plan.InPlace {
		fmt.Printf("  Mode:       full (in-place)\n")
		fmt.Printf("\n  Would restore %d touched path(s) to their pre-run state:\n", len(plan.TouchedPaths))
		for _, rel := range plan.TouchedPaths {
			fmt.Printf("    %s\n", rel)
		}
		fmt.Printf("  Files outside this set are not affected — no whole-repo wipe.\n")
	} else {
		cpFiles, cpDirs := countFS(plan.CheckpointPath)
		wsFiles, _ := countFS(plan.WorkspacePath)
		fmt.Printf("  Mode:       full\n")
		fmt.Printf("\n  Checkpoint: %d file(s) in %d dir(s)\n", cpFiles, cpDirs)
		fmt.Printf("  Workspace:  %d file(s) currently\n", wsFiles)
		fmt.Printf("  Would: remove workspace directory, copy checkpoint in.\n")
	}
	fmt.Printf("\nRun without --dry-run to perform the restore.\n")
	return nil
}

// --- confirmation -----------------------------------------------------------

func confirmPrompt(plan rollback.Plan) error {
	switch {
	case plan.Path != "":
		fmt.Printf("This will restore '%s' from checkpoint %s in:\n  %s\n", plan.Path, plan.Checkpoint, plan.WorkspacePath)
	case plan.InPlace:
		fmt.Printf("This will restore %d touched path(s) in your real repository at:\n  %s\nto their state at checkpoint %s from run %s.\nFiles outside that set are not affected.\n", len(plan.TouchedPaths), plan.WorkspacePath, plan.Checkpoint, plan.RunID)
	default:
		fmt.Printf("This will overwrite the workspace at:\n  %s\nwith checkpoint %s from run %s.\n", plan.WorkspacePath, plan.Checkpoint, plan.RunID)
	}
	fmt.Printf("This cannot be undone. Continue? [y/N] ")
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	if ans := strings.TrimSpace(strings.ToLower(sc.Text())); ans != "y" && ans != "yes" {
		return fmt.Errorf("rollback cancelled")
	}
	return nil
}

// --- helpers ----------------------------------------------------------------

func fsExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func countFS(root string) (files, dirs int) {
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			dirs++
		} else {
			files++
		}
		return nil
	})
	return
}
