package runmeta

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/policy"
)

type VerifyResult struct {
	RunID            string `json:"run_id"`
	DigestPresent    bool   `json:"digest_present"`
	SignaturePresent bool   `json:"signature_present"`
	Verified         bool   `json:"verified"`
	Status           string `json:"status"`
	SigningKeyID     string `json:"signing_key_id,omitempty"`
}

func VerifyRun(runID string, manifest RunManifest) (VerifyResult, error) {
	res := VerifyResult{RunID: runID, SigningKeyID: manifest.Digest.SigningKeyID}
	runDir := filepath.Join(".airlock", "runs", runID)
	dPath := filepath.Join(runDir, "run_digest.json")
	b, err := os.ReadFile(dPath)
	if err != nil {
		res.Status = "missing-digest"
		return res, nil
	}
	res.DigestPresent = true
	var stored RunDigest
	if err := json.Unmarshal(b, &stored); err != nil {
		res.Status = "invalid-digest"
		return res, nil
	}
	calc, err := BuildDigest(runID, runDir)
	if err != nil {
		return res, err
	}
	if !equalStringMap(stored.Files, calc.Files) {
		res.Status = "hash-mismatch"
		return res, nil
	}
	sigPath := filepath.Join(runDir, "run_digest.sig")
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		res.Verified = true
		res.Status = "verified-unsigned"
		return res, nil
	}
	res.SignaturePresent = true
	sig, err := parseSignature(sigRaw)
	if err != nil {
		res.Status = "invalid-signature-format"
		return res, nil
	}
	pub, err := loadVerifyPublicKey(manifest)
	if err != nil {
		res.Status = "signature-present-key-unavailable"
		return res, nil
	}
	h := sha256.Sum256(b)
	if !ed25519.Verify(pub, h[:], sig) {
		res.Status = "signature-invalid"
		return res, nil
	}
	res.Verified = true
	res.Status = "verified-signed"
	return res, nil
}

func loadVerifyPublicKey(m RunManifest) (ed25519.PublicKey, error) {
	if p := os.Getenv("AIRLOCK_SIGNING_PUB_KEY"); p != "" {
		return readPublicKey(p)
	}
	if p := os.Getenv("AIRLOCK_SIGNING_KEY"); p != "" {
		priv, err := readPrivateKey(p)
		if err != nil {
			return nil, err
		}
		return priv.Public().(ed25519.PublicKey), nil
	}
	if p := strings.TrimSpace(m.PolicySummary.PolicyPath); p != "" {
		if cfg, err := policy.Load(p); err == nil {
			if cfg.Signing.PublicKey != "" {
				return readPublicKey(cfg.Signing.PublicKey)
			}
			if cfg.Signing.PrivateKey != "" {
				priv, err := readPrivateKey(cfg.Signing.PrivateKey)
				if err == nil {
					return priv.Public().(ed25519.PublicKey), nil
				}
			}
		}
	}
	return nil, os.ErrNotExist
}

func readPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if raw, err := hex.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, os.ErrInvalid
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if raw, err := hex.DecodeString(s); err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw), nil
		}
		if len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw), nil
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		if len(raw) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(raw), nil
		}
		if len(raw) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(raw), nil
		}
	}
	return nil, os.ErrInvalid
}

func parseSignature(b []byte) ([]byte, error) {
	s := strings.TrimSpace(string(b))
	if raw, err := hex.DecodeString(s); err == nil && len(raw) == ed25519.SignatureSize {
		return raw, nil
	}
	if len(b) == ed25519.SignatureSize {
		return b, nil
	}
	return nil, os.ErrInvalid
}

func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
