package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mirelahmed-commits/SentinelAirlock/internal/fleet"
	"github.com/spf13/cobra"
)

// fleetCmd wires the Airlock Fleet control-plane CLI: coordination,
// inventory, desired-state policy distribution, and the trust operations that
// make those meaningful -- enrollment tokens, credential revocation, signed
// policy, and the fleet alert feed. It never performs filesystem-policy
// enforcement, which stays entirely local to each Sentinel (see
// internal/cli/sentinel.go), and it has no command-execution surface of any
// kind: the protocol carries desired policy and identity status, never
// commands.
func fleetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Airlock Fleet control plane -- Sentinel enrollment, heartbeats, inventory, and policy distribution",
	}
	cmd.AddCommand(fleetServeCmd())
	cmd.AddCommand(fleetInitCmd())
	cmd.AddCommand(fleetListCmd())
	cmd.AddCommand(fleetStatusCmd())
	cmd.AddCommand(fleetPolicyCmd())
	cmd.AddCommand(fleetEnrollTokenCmd())
	cmd.AddCommand(fleetRevokeCmd())
	cmd.AddCommand(fleetAlertsCmd())
	return cmd
}

func defaultFleetDBPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".airlock", "fleet.json")
	}
	return filepath.Join(".airlock", "fleet.json")
}

// defaultFleetSigningKeyPath is where the control plane's Ed25519 policy
// signing key lives. It sits beside the fleet stores, and is created 0600 by
// LoadOrCreateSigningKey.
func defaultFleetSigningKeyPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".airlock", "fleet-signing-key")
	}
	return filepath.Join(".airlock", "fleet-signing-key")
}

// fleetInitCmd bootstraps a control plane's signing identity without starting
// it, so an operator can distribute the public key before any Sentinel
// enrolls. It prints the key id and PUBLIC key only -- the private key is
// written to disk at 0600 and never displayed, logged, or returned by any
// API.
func fleetInitCmd() *cobra.Command {
	var keyPath string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create the control plane's policy signing key (idempotent)",
		Long: `Creates the Ed25519 key this control plane signs Fleet policy with.

The private key is written with owner-only permissions (0600) and is never
printed, logged, or exposed through any API. The public key is written
alongside it as <path>.pub and is safe to distribute -- Sentinels use it to
verify that a policy really came from this control plane.

Running this twice is safe: an existing key is loaded, not replaced.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(keyPath) == "" {
				keyPath = defaultFleetSigningKeyPath()
			}
			key, created, err := fleet.LoadOrCreateSigningKey(keyPath)
			if err != nil {
				return err
			}
			if created {
				fmt.Println("Created a new Fleet policy signing key.")
			} else {
				fmt.Println("Fleet policy signing key already exists (not replaced).")
			}
			fmt.Printf("Key file:   %s (private -- keep owner-only, never share)\n", keyPath)
			fmt.Printf("Public key: %s.pub\n", keyPath)
			fmt.Printf("Key ID:     %s\n", key.KeyID)
			fmt.Printf("Public:     %s\n", key.PublicKeyHex())
			fmt.Println()
			fmt.Println("Distribute the PUBLIC key to Sentinels that should pin it explicitly:")
			fmt.Printf("  airlock sentinel --repo . --fleet <url> --fleet-pubkey %s.pub\n", keyPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "Signing key path (default ~/.airlock/fleet-signing-key)")
	return cmd
}

func fleetServeCmd() *cobra.Command {
	var listen, dbPath, policyDBPath, authDBPath, alertDBPath, keyPath, token string
	var tlsCert, tlsKey string
	var requireEnrollment bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Airlock Fleet control plane",
		Long: `Starts the coordination/inventory plane for many Sentinels.

    Airlock Fleet Control Plane
             |
             +-- Sentinel A (repo A)
             +-- Sentinel B (repo B)
             +-- Sentinel C (repo C)

The control plane is NOT in the filesystem-policy decision path. Every
Sentinel allows/denies/reverts filesystem mutations entirely from its own
local policy engine; enrollment and heartbeats are asynchronous management
traffic layered on top. If this process is unreachable or stopped, every
enrolled Sentinel keeps governing its repository locally and reconnects
automatically once this process comes back -- no Sentinel restart required.

Runs in the foreground (like 'airlock worker start'); Ctrl-C to stop, or
manage it with your own process supervisor.

TRUST POSTURE

  --require-enrollment  Production posture. Every Sentinel must present a
                        one-time enrollment token to enroll, and its own
                        durable credential on every request thereafter.

  (default)             Development posture. A Sentinel that has never been
                        issued a credential may enroll and heartbeat without
                        one. A Sentinel that HAS a credential must always
                        present it -- that half is unconditional, so an
                        enrolled identity can never be impersonated in either
                        posture.

  --tls-cert/--tls-key  Serve HTTPS. Bearer credentials over plaintext HTTP
                        are only appropriate for loopback development; for
                        anything else use these (or a TLS-terminating proxy).

Policy is signed with the control plane's Ed25519 key (see 'airlock fleet
init'). The private key is never printed and never exposed through any API.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(dbPath) == "" {
				dbPath = defaultFleetDBPath()
			}
			dir := filepath.Dir(dbPath)
			if strings.TrimSpace(policyDBPath) == "" {
				policyDBPath = filepath.Join(dir, "fleet-policies.json")
			}
			if strings.TrimSpace(authDBPath) == "" {
				authDBPath = filepath.Join(dir, "fleet-auth.json")
			}
			if strings.TrimSpace(alertDBPath) == "" {
				alertDBPath = filepath.Join(dir, "fleet-alerts.json")
			}
			if strings.TrimSpace(keyPath) == "" {
				keyPath = defaultFleetSigningKeyPath()
			}
			store, err := fleet.OpenStore(dbPath)
			if err != nil {
				return fmt.Errorf("could not open fleet store %s: %w", dbPath, err)
			}
			policyStore, err := fleet.OpenPolicyStore(policyDBPath)
			if err != nil {
				return fmt.Errorf("could not open fleet policy store %s: %w", policyDBPath, err)
			}
			authStore, err := fleet.OpenAuthStore(authDBPath)
			if err != nil {
				return fmt.Errorf("could not open fleet auth store %s: %w", authDBPath, err)
			}
			alertStore, err := fleet.OpenAlertStore(alertDBPath)
			if err != nil {
				return fmt.Errorf("could not open fleet alert store %s: %w", alertDBPath, err)
			}
			signingKey, createdKey, err := fleet.LoadOrCreateSigningKey(keyPath)
			if err != nil {
				return fmt.Errorf("could not load fleet signing key %s: %w", keyPath, err)
			}
			if (tlsCert == "") != (tlsKey == "") {
				return fmt.Errorf("--tls-cert and --tls-key must be provided together")
			}

			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("unable to bind %s: %w", listen, err)
			}
			srv := fleet.NewServerWithOptions(store, policyStore, token, fleet.ServerOptions{
				AuthStore:         authStore,
				AlertStore:        alertStore,
				SigningKey:        signingKey,
				RequireEnrollment: requireEnrollment,
			})

			scheme := "http"
			if tlsCert != "" {
				scheme = "https"
			}
			fmt.Println("Airlock Fleet control plane started")
			fmt.Printf("Listen:       %s://%s\n", scheme, ln.Addr().String())
			fmt.Printf("Store:        %s\n", dbPath)
			fmt.Printf("Policy store: %s\n", policyDBPath)
			fmt.Printf("Auth store:   %s\n", authDBPath)
			fmt.Printf("Alert store:  %s\n", alertDBPath)
			fmt.Printf("Signing key:  %s (key id %s)\n", keyPath, signingKey.KeyID)
			if createdKey {
				fmt.Println("              (generated just now; distribute the .pub file to pin it on Sentinels)")
			}
			if requireEnrollment {
				fmt.Println("Enrollment:   REQUIRED -- create a token with 'airlock fleet enroll-token create'")
			} else {
				fmt.Println("Enrollment:   optional (development posture). Enrolled Sentinels still require their own credential.")
				fmt.Println("              Use --require-enrollment for a deployment where identity must be proven.")
			}
			if strings.TrimSpace(token) == "" {
				fmt.Println("Operator API: UNAUTHENTICATED (no --token set)")
			} else {
				fmt.Println("Operator API: shared token required")
			}
			if tlsCert == "" && !isLoopbackListenAddr(ln.Addr().String()) {
				fmt.Println("WARNING:      serving plaintext HTTP on a non-loopback address. Credentials will cross")
				fmt.Println("              the network unencrypted. Use --tls-cert/--tls-key or a TLS proxy.")
			}
			fmt.Println("Ctrl-C to stop. Enrolled Sentinels keep governing locally regardless of this process's availability.")

			if tlsCert != "" {
				return http.ServeTLS(ln, srv.Handler(), tlsCert, tlsKey)
			}
			return http.Serve(ln, srv.Handler())
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:9090", "Listen address")
	cmd.Flags().StringVar(&dbPath, "db", "", "Fleet inventory storage path (default ~/.airlock/fleet.json)")
	cmd.Flags().StringVar(&policyDBPath, "policy-db", "", "Fleet policy storage path (default: fleet-policies.json next to --db)")
	cmd.Flags().StringVar(&authDBPath, "auth-db", "", "Enrollment token/credential storage path (default: fleet-auth.json next to --db)")
	cmd.Flags().StringVar(&alertDBPath, "alert-db", "", "Fleet alert storage path (default: fleet-alerts.json next to --db)")
	cmd.Flags().StringVar(&keyPath, "signing-key", "", "Policy signing key path (default ~/.airlock/fleet-signing-key; created if absent)")
	cmd.Flags().StringVar(&token, "token", "", "Optional shared operator token")
	cmd.Flags().BoolVar(&requireEnrollment, "require-enrollment", false, "Require a one-time enrollment token and per-Sentinel credentials (production posture)")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file (serve HTTPS)")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS private key file (serve HTTPS)")
	return cmd
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func fleetListCmd() *cobra.Command {
	var fleetURL, token string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Sentinels known to a fleet control plane",
		RunE: func(cmd *cobra.Command, args []string) error {
			snap, err := fetchFleetSnapshot(fleetURL, token)
			if err != nil {
				return err
			}
			printFleetTable(fleetURL, snap)
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet auth token")
	return cmd
}

func fleetStatusCmd() *cobra.Command {
	var fleetURL, token string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show fleet health summary (active/offline Sentinel counts)",
		RunE: func(cmd *cobra.Command, args []string) error {
			snap, err := fetchFleetSnapshot(fleetURL, token)
			if err != nil {
				return err
			}
			fmt.Printf("Fleet:   %s\n", fleetURL)
			fmt.Printf("Active:  %d\n", snap.Active)
			fmt.Printf("Offline: %d\n", snap.Offline)
			fmt.Printf("Total:   %d\n", len(snap.Sentinels))
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet auth token")
	return cmd
}

func fetchFleetSnapshot(fleetURL, token string) (*fleet.Snapshot, error) {
	fleetURL = strings.TrimSpace(fleetURL)
	if fleetURL == "" {
		return nil, fmt.Errorf("--fleet is required")
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(fleetURL, "/")+"/api/fleet/sentinels", nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach fleet control plane at %s: %w", fleetURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fleet control plane at %s returned %s", fleetURL, resp.Status)
	}
	var snap fleet.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		return nil, fmt.Errorf("could not parse fleet response: %w", err)
	}
	return &snap, nil
}

func printFleetTable(fleetURL string, snap *fleet.Snapshot) {
	fmt.Println("AIRLOCK FLEET")
	fmt.Println()
	fmt.Printf("%d Active\n%d Offline\n%d Drifted\n%d Revoked\n\n", snap.Active, snap.Offline, snap.Drifted, snap.Revoked)
	if len(snap.Sentinels) == 0 {
		fmt.Printf("No Sentinels enrolled with %s yet.\n", fleetURL)
		fmt.Println("Enroll one with: airlock sentinel --repo . --fleet " + fleetURL + " --background")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "SENTINEL\tSTATUS\tIDENTITY\tREPOSITORY\tDESIRED\tACTUAL\tSYNC\tSIGNATURE\tHEARTBEAT")
	for _, sv := range snap.Sentinels {
		id := sv.SentinelID
		if len(id) > 8 {
			id = id[:8]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			id, sv.Health, sv.Identity, sv.RepoPath,
			policyRefLabel(sv.DesiredPolicyID, itoaOrDash(sv.DesiredPolicyVersion)),
			policyRefLabel(sv.PolicyID, sv.PolicyVersion), syncLabel(sv.PolicyState),
			dashIfEmpty(sv.SignatureState), fleet.FormatAge(sv.LastHeartbeat))
	}
	_ = w.Flush()
}

func policyRefLabel(id, version string) string {
	if id == "" {
		return "-"
	}
	if version == "" || version == "-" {
		return id
	}
	return id + " v" + version
}

func itoaOrDash(v int) string {
	if v <= 0 {
		return "-"
	}
	return strconv.Itoa(v)
}

func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func syncLabel(policyState string) string {
	if policyState == "" {
		return "-"
	}
	return policyState
}

// --- Policy resource CLI (Prompt 14A) ---------------------------------------
//
// `--file` always means "read this local file's content and send it" -- the
// control plane never accepts or dereferences a filesystem path itself (see
// internal/fleet/server.go's policy handlers), so there is no way to ask a
// remote fleet control plane to read an arbitrary path on its own host.

func fleetPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage Fleet-distributed desired-state policies",
	}
	cmd.AddCommand(fleetPolicyListCmd())
	cmd.AddCommand(fleetPolicyShowCmd())
	cmd.AddCommand(fleetPolicyCreateCmd())
	cmd.AddCommand(fleetPolicyUpdateCmd())
	cmd.AddCommand(fleetPolicyAssignCmd())
	return cmd
}

type policyVersionSummary struct {
	PolicyID    string    `json:"policy_id"`
	Version     int       `json:"version"`
	Hash        string    `json:"hash"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func fleetPolicyListCmd() *cobra.Command {
	var fleetURL, token string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Fleet-managed policies (latest version of each)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var summaries []policyVersionSummary
			if err := fleetGet(fleetURL, token, "/api/fleet/policies", &summaries); err != nil {
				return err
			}
			if len(summaries) == 0 {
				fmt.Println("No Fleet policies created yet.")
				fmt.Println("Create one with: airlock fleet policy create <policy-id> --file <path>")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "POLICY\tLATEST VERSION\tHASH\tDESCRIPTION")
			for _, p := range summaries {
				fmt.Fprintf(w, "%s\tv%d\t%s\t%s\n", p.PolicyID, p.Version, p.Hash, p.Description)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet auth token")
	return cmd
}

func fleetPolicyShowCmd() *cobra.Command {
	var fleetURL, token string
	cmd := &cobra.Command{
		Use:   "show <policy-id>",
		Short: "Show every version of a Fleet-managed policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var summaries []policyVersionSummary
			if err := fleetGet(fleetURL, token, "/api/fleet/policies/"+args[0], &summaries); err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "VERSION\tHASH\tCREATED\tDESCRIPTION")
			for _, p := range summaries {
				fmt.Fprintf(w, "v%d\t%s\t%s\t%s\n", p.Version, p.Hash, p.CreatedAt.Format(time.RFC3339), p.Description)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet auth token")
	return cmd
}

func fleetPolicyCreateCmd() *cobra.Command {
	var fleetURL, token, file, description string
	cmd := &cobra.Command{
		Use:   "create <policy-id>",
		Short: "Create a brand-new Fleet-managed policy (its first version)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := readPolicyFile(file)
			if err != nil {
				return err
			}
			var summary policyVersionSummary
			body := map[string]string{"policy_id": args[0], "description": description, "yaml": content}
			if err := fleetPost(fleetURL, token, "/api/fleet/policies", body, &summary); err != nil {
				return err
			}
			fmt.Printf("Created policy %s v%d (hash %s)\n", summary.PolicyID, summary.Version, summary.Hash)
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet auth token")
	cmd.Flags().StringVar(&file, "file", "", "Path to a local airlock.yaml-shaped policy document (required)")
	cmd.Flags().StringVar(&description, "description", "", "Optional human-readable description")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func fleetPolicyUpdateCmd() *cobra.Command {
	var fleetURL, token, file, description string
	cmd := &cobra.Command{
		Use:   "update <policy-id>",
		Short: "Add a new version to an existing Fleet-managed policy",
		Long: `Adds a new, immutable version to an existing policy -- it never rewrites
an existing version's content. "airlock fleet policy show <id>" lists every
version that has ever existed, including this new one, by its own number.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := readPolicyFile(file)
			if err != nil {
				return err
			}
			var summary policyVersionSummary
			body := map[string]string{"description": description, "yaml": content}
			if err := fleetPost(fleetURL, token, "/api/fleet/policies/"+args[0]+"/versions", body, &summary); err != nil {
				return err
			}
			fmt.Printf("Created %s v%d (hash %s)\n", summary.PolicyID, summary.Version, summary.Hash)
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet auth token")
	cmd.Flags().StringVar(&file, "file", "", "Path to a local airlock.yaml-shaped policy document (required)")
	cmd.Flags().StringVar(&description, "description", "", "Optional human-readable description")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func fleetPolicyAssignCmd() *cobra.Command {
	var fleetURL, token, sentinelID string
	var version int
	cmd := &cobra.Command{
		Use:   "assign <policy-id>",
		Short: "Assign a specific policy version to a Sentinel as its desired state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(sentinelID) == "" {
				return fmt.Errorf("--sentinel is required")
			}
			if version <= 0 {
				return fmt.Errorf("--version is required and must be positive")
			}
			body := map[string]any{"policy_id": args[0], "version": version}
			var view fleet.SentinelView
			path := "/api/fleet/sentinels/" + sentinelID + "/assign"
			if err := fleetPost(fleetURL, token, path, body, &view); err != nil {
				return err
			}
			fmt.Printf("Assigned %s v%d to Sentinel %s\n", args[0], version, sentinelID)
			fmt.Println("It will pick this up on its next heartbeat -- no restart required.")
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet auth token")
	cmd.Flags().StringVar(&sentinelID, "sentinel", "", "Target Sentinel ID (see 'airlock fleet list')")
	cmd.Flags().IntVar(&version, "version", 0, "Policy version to assign")
	return cmd
}

func readPolicyFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("--file is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("could not read %s: %w", path, err)
	}
	if strings.TrimSpace(string(b)) == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return string(b), nil
}

func fleetGet(fleetURL, token, path string, out any) error {
	fleetURL = strings.TrimSpace(fleetURL)
	if fleetURL == "" {
		return fmt.Errorf("--fleet is required")
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(fleetURL, "/")+path, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach fleet control plane at %s: %w", fleetURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fleet control plane returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func fleetPost(fleetURL, token, path string, body, out any) error {
	fleetURL = strings.TrimSpace(fleetURL)
	if fleetURL == "" {
		return fmt.Errorf("--fleet is required")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(fleetURL, "/")+path, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach fleet control plane at %s: %w", fleetURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("fleet control plane returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// --- Trust CLI (Prompt 14B) -------------------------------------------------

func fleetEnrollTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll-token",
		Short: "Create, list, and revoke one-time Sentinel enrollment tokens",
	}
	cmd.AddCommand(fleetEnrollTokenCreateCmd())
	cmd.AddCommand(fleetEnrollTokenListCmd())
	cmd.AddCommand(fleetEnrollTokenRevokeCmd())
	return cmd
}

type enrollTokenCreated struct {
	ID    string    `json:"id"`
	Token string    `json:"token"`
	Note  string    `json:"note"`
	Ends  time.Time `json:"expires_at"`
}

func fleetEnrollTokenCreateCmd() *cobra.Command {
	var fleetURL, token, description string
	var ttlMinutes int
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Mint a one-time enrollment token for a new Sentinel",
		Long: `Creates a single-use, expiring token that authorizes exactly one Sentinel
to enroll and receive its own durable credential.

The token is shown ONCE. The control plane stores only its hash and cannot
display it again -- if it is lost, revoke it and create another. Deliver it
to the target machine out-of-band, the same way you would any other secret.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"description": description, "ttl_seconds": ttlMinutes * 60}
			var created enrollTokenCreated
			if err := fleetPost(fleetURL, token, "/api/fleet/enroll-tokens", body, &created); err != nil {
				return err
			}
			fmt.Println("Enrollment token created. It is shown once and cannot be retrieved again.")
			fmt.Printf("  Token:   %s\n", created.Token)
			fmt.Printf("  ID:      %s\n", created.ID)
			fmt.Printf("  Expires: %s\n", created.Ends.Format(time.RFC3339))
			fmt.Println()
			fmt.Println("Enroll a Sentinel with it:")
			fmt.Printf("  airlock sentinel --repo . --fleet %s --fleet-enroll-token %s --background\n", fleetURL, created.Token)
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet operator token")
	cmd.Flags().StringVar(&description, "description", "", "Optional note about who this token is for")
	cmd.Flags().IntVar(&ttlMinutes, "ttl-minutes", 60, "How long the token stays usable")
	return cmd
}

// enrollTokenRow mirrors fleet.EnrollTokenRecord for display. Note what is
// absent: no token material of any kind, only its hash-derived id.
type enrollTokenRow struct {
	ID          string     `json:"id"`
	Description string     `json:"description,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
	UsedBy      string     `json:"used_by,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

func (r enrollTokenRow) state(now time.Time) string {
	switch {
	case r.RevokedAt != nil:
		return "REVOKED"
	case r.UsedAt != nil:
		return "USED"
	case now.After(r.ExpiresAt):
		return "EXPIRED"
	default:
		return "VALID"
	}
}

func fleetEnrollTokenListCmd() *cobra.Command {
	var fleetURL, token string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrollment tokens and their state (never their values)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var rows []enrollTokenRow
			if err := fleetGet(fleetURL, token, "/api/fleet/enroll-tokens", &rows); err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Println("No enrollment tokens have been created.")
				fmt.Println("Create one with: airlock fleet enroll-token create")
				return nil
			}
			now := time.Now().UTC()
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATE\tEXPIRES\tUSED BY\tDESCRIPTION")
			for _, r := range rows {
				usedBy := r.UsedBy
				if usedBy == "" {
					usedBy = "-"
				} else if len(usedBy) > 8 {
					usedBy = usedBy[:8]
				}
				desc := r.Description
				if desc == "" {
					desc = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.state(now), r.ExpiresAt.Format(time.RFC3339), usedBy, desc)
			}
			_ = w.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet operator token")
	return cmd
}

func fleetEnrollTokenRevokeCmd() *cobra.Command {
	var fleetURL, token string
	cmd := &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Make an unused enrollment token permanently unusable",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := fleetPost(fleetURL, token, "/api/fleet/enroll-tokens/"+args[0]+"/revoke", map[string]any{}, &out); err != nil {
				return err
			}
			fmt.Printf("Enrollment token %s revoked.\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet operator token")
	return cmd
}

func fleetRevokeCmd() *cobra.Command {
	var fleetURL, token, reason string
	cmd := &cobra.Command{
		Use:   "revoke <sentinel-id>",
		Short: "Revoke a Sentinel's Fleet credential",
		Long: `Revokes a Sentinel's credential so it can no longer participate in Fleet.

What this does:   the credential stops authenticating. The Sentinel can no
                  longer heartbeat, fetch policy, or upload reports.

What it does NOT do: stop that Sentinel from governing its repository. It
                  keeps enforcing its last-known-good policy locally and
                  reports its revoked Fleet identity in its own status.

That boundary is deliberate. If revocation could switch off local protection,
central revocation would become a remote off-switch for the thing Airlock
exists to do.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var view fleet.SentinelView
			if err := fleetPost(fleetURL, token, "/api/fleet/sentinels/"+args[0]+"/revoke", map[string]any{"reason": reason}, &view); err != nil {
				return err
			}
			fmt.Printf("Sentinel %s credential REVOKED.\n", args[0])
			fmt.Println("It can no longer participate in Fleet.")
			fmt.Println("It continues enforcing its last-known-good policy locally -- revocation is not a remote stop.")
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet operator token")
	cmd.Flags().StringVar(&reason, "reason", "", "Why this credential is being revoked (recorded for operators)")
	return cmd
}

func fleetAlertsCmd() *cobra.Command {
	var fleetURL, token string
	var limit int
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Show recent fleet-wide governance alerts reported by Sentinels",
		Long: `Shows recent metadata-only alerts (denials, reverts, revert failures, policy
applications, trust rejections) uploaded by enrolled Sentinels.

This is a fleet-level activity view, not an evidence store. Raw evidence --
diffs, contents, full event logs -- never leaves the machine that produced it
and remains authoritative there ('airlock inspect/replay/verify').`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var alerts []fleet.Report
			if err := fleetGet(fleetURL, token, fmt.Sprintf("/api/fleet/alerts?limit=%d", limit), &alerts); err != nil {
				return err
			}
			if len(alerts) == 0 {
				fmt.Println("No fleet alerts reported yet.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(w, "WHEN\tSENTINEL\tREPOSITORY\tTYPE\tPATH")
			for _, a := range alerts {
				id := a.SentinelID
				if len(id) > 8 {
					id = id[:8]
				}
				path := a.Path
				if path == "" {
					path = a.Summary
				}
				if path == "" {
					path = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", fleet.FormatAge(a.At), id, filepath.Base(a.RepoPath), a.Type, path)
			}
			_ = w.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&fleetURL, "fleet", "http://127.0.0.1:9090", "Fleet control plane URL")
	cmd.Flags().StringVar(&token, "token", "", "Fleet operator token")
	cmd.Flags().IntVar(&limit, "limit", 30, "How many recent alerts to show")
	return cmd
}
