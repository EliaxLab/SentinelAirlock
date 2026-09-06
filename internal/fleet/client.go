package fleet

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Client is the Sentinel-side fleet client. Every call uses a short, bounded
// HTTP timeout (ClientTimeout) so a slow or unreachable control plane can
// never block for long -- and the caller (internal/cli/sentinel.go) runs
// every Client call from a goroutine entirely independent of the recorder,
// so even a full timeout never delays local filesystem enforcement. This is
// the mechanical enforcement of the fleet-foundation's non-negotiable
// disconnected-operation requirement.
type Client struct {
	baseURL    string
	token      string
	credential string
	http       *http.Client
}

// NewClient builds a Client for baseURL (the control plane's address).
// token is optional; when set it is sent as both a Bearer Authorization
// header and X-Airlock-Fleet-Token, matching the control plane's operator
// token check.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   strings.TrimSpace(token),
		http:    &http.Client{Timeout: ClientTimeout},
	}
}

// SetCredential attaches this Sentinel's durable per-Sentinel credential
// (Prompt 14B). Once set, every request carries it and the control plane
// resolves this Sentinel's identity from it rather than from any field in the
// request body.
func (c *Client) SetCredential(credential string) {
	c.credential = strings.TrimSpace(credential)
}

// HasCredential reports whether this client is authenticating as a specific
// enrolled Sentinel.
func (c *Client) HasCredential() bool { return c.credential != "" }

// UsesTLS reports whether the control-plane URL is https. Used to warn
// operators who are about to send credentials over plaintext HTTP to a
// non-loopback host -- see internal/cli/sentinel.go's transport check.
func (c *Client) UsesTLS() bool { return strings.HasPrefix(c.baseURL, "https://") }

// BaseURL returns the configured control-plane address.
func (c *Client) BaseURL() string { return c.baseURL }

// SetRootCA makes this client trust the PEM certificate bundle at path in
// addition to nothing else -- for a self-hosted control plane fronted by a
// private CA or a self-signed certificate. Certificate verification stays
// fully enabled; this adds a trust anchor rather than disabling checking,
// and there is deliberately no option in this client to skip verification.
func (c *Client) SetRootCA(path string) error {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("could not read fleet CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("fleet CA bundle %s contains no usable certificates", path)
	}
	c.http = &http.Client{
		Timeout:   ClientTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	return nil
}

// Enroll registers or refreshes this Sentinel's identity with the control
// plane and returns the response, which on a first enrollment carries the
// Sentinel's durable credential and the control plane's policy-signing public
// key.
func (c *Client) Enroll(req EnrollRequest) (EnrollResponse, error) {
	var resp EnrollResponse
	err := c.post("/api/fleet/enroll", req, &resp)
	return resp, err
}

// SendReports uploads a batch of buffered reports. The response names exactly
// which report ids the control plane now holds, so the caller only clears
// those from its outbox.
func (c *Client) SendReports(batch ReportBatch) (ReportBatchResponse, error) {
	var resp ReportBatchResponse
	err := c.post("/api/fleet/reports", batch, &resp)
	return resp, err
}

// Heartbeat reports current liveness/status/counters and returns the
// control plane's response, which carries the Sentinel's current desired
// policy (if one has been assigned) -- see internal/cli/sentinel.go's
// fleetLoop for how that drives reconciliation. It is safe to call even if
// Enroll has never succeeded -- the control plane creates a minimal record
// from whatever a heartbeat carries rather than rejecting it.
func (c *Client) Heartbeat(req HeartbeatRequest) (HeartbeatResponse, error) {
	var resp HeartbeatResponse
	err := c.post("/api/fleet/heartbeat", req, &resp)
	return resp, err
}

// GetPolicyVersion fetches one specific, immutable version of a named
// Fleet-managed policy, including its full YAML content -- what a Sentinel
// calls when it discovers (via a heartbeat response) that its desired
// policy differs from what it is currently enforcing.
func (c *Client) GetPolicyVersion(policyID string, version int) (PolicyVersion, error) {
	var v PolicyVersion
	path := "/api/fleet/policies/" + policyID + "/versions/" + strconv.Itoa(version)
	err := c.get(path, &v)
	return v, err
}

func (c *Client) post(path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	return c.do(httpReq, path, out)
}

func (c *Client) get(path string, out any) error {
	httpReq, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(httpReq, path, out)
}

func (c *Client) do(httpReq *http.Request, path string, out any) error {
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.credential != "" {
		httpReq.Header.Set(CredentialHeader, c.credential)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden && isRevocationBody(resp.Body) {
			return ErrCredentialRevoked
		}
		return fmt.Errorf("fleet %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// isRevocationBody recognizes the control plane's stable revocation token, so
// a Sentinel can tell "my identity was revoked" apart from a generic
// rejection. That distinction is what lets it report the state locally
// instead of retrying forever as if the network were at fault.
func isRevocationBody(body io.Reader) bool {
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(body, 1<<12)).Decode(&payload); err != nil {
		return false
	}
	return payload.Error == ErrorCredentialRevoked
}
