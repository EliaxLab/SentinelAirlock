package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/index"
	"github.com/EliaxLab/SentinelAirlock/internal/web"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	var listen string
	var open bool
	var noOpen bool
	var readOnly bool
	var port int
	var background bool
	var status bool
	var stop bool
	var managed bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start local web evidence viewer",
		Long: `Start the local web evidence viewer.

Two modes:
  Read-only inspection:  airlock serve --read-only    (safe to share; state
                         changes appear as terminal commands, never buttons)
  Operator (default):    airlock serve                (local trusted control;
                         review / rollback / export can run from the UI)

Lifecycle:
  airlock serve                      foreground operator viewer
  airlock serve --read-only          foreground read-only viewer
  airlock serve --background --open  detached viewer, returns the terminal
  airlock serve --status             show the running viewer (mode/URL/PID/log)
  airlock serve --stop               stop the running viewer

Rollback from the UI (operator mode only) follows the run's execution mode:
workspace/container runs restore their isolated workspace; sandbox=off and
stopped Sentinel sessions restore only recorded touched paths in the real repo.
Rollback is disabled while a Sentinel session is active.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Lifecycle sub-actions.
			if status {
				return viewerStatus()
			}
			if stop {
				return viewerStop()
			}

			if noOpen {
				open = false
			}
			// Resolve the concrete listen address.
			if port > 0 {
				host := "127.0.0.1"
				if strings.Contains(listen, ":") {
					parts := strings.Split(listen, ":")
					host = strings.Join(parts[:len(parts)-1], ":")
				}
				listen = host + ":" + strconv.Itoa(port)
			}

			mode := viewerModeLabel(readOnly)

			// Refuse to start a duplicate viewer.
			if existing, ok := runningViewer(); ok {
				fmt.Printf("A local viewer is already running.\n")
				fmt.Printf("  Mode: %s\n  URL:  %s\n  PID:  %d\n  Log:  %s\n", existing.Mode, existing.URL, existing.PID, existing.Log)
				fmt.Printf("Stop it first with: airlock serve --stop\n")
				return nil
			}

			// Background: spawn a detached child and return the terminal.
			if background {
				return startViewerBackground(listen, readOnly, open)
			}

			// Foreground (direct, or the managed background child).
			refreshIndex()
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				if isPortInUse(err) {
					if host, portStr, splitErr := net.SplitHostPort(listen); splitErr == nil {
						if port, atoiErr := strconv.Atoi(portStr); atoiErr == nil {
							alts := findAlternativePorts(host, port, 3)
							if len(alts) > 0 {
								var sb strings.Builder
								fmt.Fprintf(&sb, "Port %d is already in use.\n\nAvailable alternatives:\n", port)
								for _, p := range alts {
									fmt.Fprintf(&sb, "  airlock serve --port %d\n", p)
								}
								cmd.SilenceUsage = true
								return errors.New(strings.TrimRight(sb.String(), "\n"))
							}
						}
					}
				}
				return fmt.Errorf("unable to bind %s: %w", listen, err)
			}
			url := "http://" + ln.Addr().String()

			logDesc := "(foreground terminal)"
			if managed {
				logDesc = viewerLogPath()
			}
			_ = writeViewerMeta(viewerMeta{
				PID:        os.Getpid(),
				Mode:       mode,
				URL:        url,
				Listen:     ln.Addr().String(),
				Log:        logDesc,
				Started:    time.Now().Format(time.RFC3339),
				Background: managed,
			})
			// Remove our metadata on clean shutdown so --status stays accurate.
			installViewerCleanup()

			store, _ := index.Load(index.DefaultPath())
			fmt.Println("Viewer started")
			fmt.Printf("Mode: %s\n", mode)
			fmt.Printf("URL: %s\n", url)
			fmt.Printf("Read-only: %t\n", readOnly)
			fmt.Printf("Index: %s\n", index.DefaultPath())
			fmt.Printf("Runs indexed: %d\n", len(store.Runs))
			if !managed {
				fmt.Printf("Stop: Ctrl-C  (or run in background: airlock serve --background)\n")
			}
			shutdownFn := func() {
				removeViewerMeta()
				os.Exit(0)
			}
			repoAbs, absErr := filepath.Abs(".")
			if absErr != nil {
				return fmt.Errorf("resolve viewer repository: %w", absErr)
			}
			return web.StartOnListenerWithOptions(ln, open, web.ServerOptions{
				ReadOnly:     readOnly,
				ShutdownFunc: shutdownFn,
				RepoPath:     repoAbs,
				SentinelStatus: func() (web.SentinelProcess, bool, error) {
					m, running, statusErr := runningSentinelDetailed(repoAbs)
					return web.SentinelProcess{
						PID: m.PID, Repo: m.Repo, SessionID: m.Session,
						StartedAt: m.Started, LogPath: m.Log, Background: m.Background,
					}, running, statusErr
				},
				SentinelStop: func() error { return sentinelStopCmd(repoAbs) },
			})
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8080", "Listen address")
	cmd.Flags().BoolVar(&open, "open", false, "Open browser")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "Do not open browser")
	cmd.Flags().IntVar(&port, "port", 0, "Port override")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "Read-only inspection mode (no mutating actions)")
	cmd.Flags().BoolVar(&background, "background", false, "Run the viewer detached in the background")
	cmd.Flags().BoolVar(&status, "status", false, "Show the running viewer's status")
	cmd.Flags().BoolVar(&stop, "stop", false, "Stop the running viewer")
	// --managed marks the detached child; it manages viewer.json + cleanup.
	cmd.Flags().BoolVar(&managed, "managed", false, "Internal: run as the managed background viewer")
	_ = cmd.Flags().MarkHidden("managed")
	return cmd
}

// isPortInUse reports whether err is an "address already in use" bind failure.
// Checks both the Unix and Windows error strings.
func isPortInUse(err error) bool {
	s := err.Error()
	return strings.Contains(s, "address already in use") ||
		strings.Contains(s, "Only one usage of each socket address")
}

// findAlternativePorts probes up to maxCount ports above startPort on the given
// host and returns those that can immediately be bound. Scans at most 20
// candidates so the error path stays fast.
func findAlternativePorts(host string, startPort, maxCount int) []int {
	var found []int
	for p := startPort + 1; p <= startPort+20 && len(found) < maxCount; p++ {
		ln, listenErr := net.Listen("tcp", host+":"+strconv.Itoa(p))
		if listenErr == nil {
			_ = ln.Close()
			found = append(found, p)
		}
	}
	return found
}

// installViewerCleanup removes the viewer metadata when the serving process is
// asked to shut down, so status/stop never report a ghost viewer.
func installViewerCleanup() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		removeViewerMeta()
		os.Exit(0)
	}()
}
