package cli

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
	"github.com/spf13/cobra"
)

func exportCmd() *cobra.Command {
	var (
		format                 string
		includeReport          bool
		includeCheckpointsMeta bool
	)
	cmd := &cobra.Command{
		Use:   "export <run_id>",
		Short: "Export run evidence bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := runmeta.LoadArtifacts(args[0])
			if err != nil {
				return err
			}
			if format != "zip" && format != "tar.gz" {
				return fmt.Errorf("unsupported format: %s", format)
			}
			metaPath := filepath.Join(a.RunDir, "build_info.json")
			meta := fmt.Sprintf("{\"version\":%q,\"commit\":%q,\"build_date\":%q}\n", Version, Commit, BuildDate)
			_ = os.WriteFile(metaPath, []byte(meta), 0o644)

			base := filepath.Join(a.RunDir, "airlock-run-"+a.RunID)
			outPath := base + ".zip"
			if format == "tar.gz" {
				outPath = base + ".tar.gz"
			}

			items := []string{"run_manifest.json", "events.jsonl", "run_digest.json", "build_info.json"}
			maybeAdd := func(name string) {
				if runmeta.Exists(filepath.Join(a.RunDir, name)) {
					items = append(items, name)
				}
			}
			maybeAdd("session_events.jsonl")
			maybeAdd("changes.patch")
			maybeAdd("run_digest.sig")
			if includeCheckpointsMeta {
				maybeAdd(filepath.Join("checkpoints", "cp-0"))
			}
			if includeReport && runmeta.Exists(filepath.Join(a.RunDir, "report")) {
				items = append(items, "report")
			}

			if format == "zip" {
				if err := writeZip(outPath, a.RunDir, items); err != nil {
					return err
				}
			} else {
				if err := writeTarGz(outPath, a.RunDir, items); err != nil {
					return err
				}
			}

			a.Manifest.Export = runmeta.ExportInfo{Path: outPath, Format: format}
			if err := runmeta.Save(a.ManifestPath, a.Manifest); err != nil {
				return err
			}
			// Rebuild digest: manifest was updated above with export metadata.
			// Without this, verify would return hash-mismatch after any export.
			if digest, err := runmeta.BuildDigest(a.RunID, a.RunDir); err == nil {
				_ = runmeta.SaveDigest(filepath.Join(a.RunDir, "run_digest.json"), digest)
			}
			fmt.Printf("Export: %s\n", outPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "zip", "Export format: zip | tar.gz")
	cmd.Flags().BoolVar(&includeReport, "include-report", true, "Include report/ folder in export")
	cmd.Flags().BoolVar(&includeCheckpointsMeta, "include-checkpoints-meta", false, "Include checkpoints metadata/files")
	return cmd
}

func writeZip(outPath, root string, items []string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	for _, item := range items {
		if err := addToZip(zw, root, item); err != nil {
			return err
		}
	}
	return nil
}

func addToZip(zw *zip.Writer, root, rel string) error {
	abs := filepath.Join(root, rel)
	info, err := os.Stat(abs)
	if err != nil {
		return nil
	}
	if info.IsDir() {
		return filepath.Walk(abs, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil || fi.IsDir() {
				return walkErr
			}
			relPath, _ := filepath.Rel(root, path)
			return addFileToZip(zw, path, relPath)
		})
	}
	return addFileToZip(zw, abs, rel)
}

func addFileToZip(zw *zip.Writer, path, rel string) error {
	rel = filepath.ToSlash(rel)
	w, err := zw.Create(rel)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func writeTarGz(outPath, root string, items []string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for _, item := range items {
		if err := addToTar(tw, root, item); err != nil {
			return err
		}
	}
	return nil
}

func addToTar(tw *tar.Writer, root, rel string) error {
	abs := filepath.Join(root, rel)
	info, err := os.Stat(abs)
	if err != nil {
		return nil
	}
	if info.IsDir() {
		return filepath.Walk(abs, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil || fi.IsDir() {
				return walkErr
			}
			relPath, _ := filepath.Rel(root, path)
			return addFileToTar(tw, path, relPath)
		})
	}
	return addFileToTar(tw, abs, rel)
}

func addFileToTar(tw *tar.Writer, path, rel string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = filepath.ToSlash(strings.TrimPrefix(rel, "./"))
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}
