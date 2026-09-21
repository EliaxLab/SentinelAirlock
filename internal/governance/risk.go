package governance

import (
	"path/filepath"
	"strings"

	"github.com/EliaxLab/SentinelAirlock/internal/policy"
)

type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

type RiskCategory string

const (
	RiskFilesystem RiskCategory = "filesystem"
	RiskCommand    RiskCategory = "command"
	RiskSecrets    RiskCategory = "secrets"
	RiskNetwork    RiskCategory = "network"
	RiskGit        RiskCategory = "git"
	RiskConfig     RiskCategory = "config"
	RiskDependency RiskCategory = "dependency"
	RiskArtifact   RiskCategory = "artifact"
)

type Assessment struct {
	Level       RiskLevel
	Category    RiskCategory
	Reason      string
	HardBlocked bool
}

func ClassifyCommand(agentCmd string) Assessment {
	c := strings.ToLower(strings.TrimSpace(agentCmd))
	if c == "" {
		return Assessment{Level: RiskMedium, Category: RiskCommand, Reason: "empty command string"}
	}
	if strings.Contains(c, "rm -rf") || strings.Contains(c, "chmod -r") || strings.Contains(c, "chown -r") {
		return Assessment{Level: RiskHigh, Category: RiskCommand, Reason: "destructive shell pattern", HardBlocked: true}
	}
	if strings.Contains(c, "chmod ") || strings.Contains(c, "chown ") ||
		strings.Contains(c, "npm install") || strings.Contains(c, "pip install") ||
		strings.Contains(c, "go get ") || strings.Contains(c, "poetry add ") {
		return Assessment{Level: RiskMedium, Category: RiskCommand, Reason: "mutates tooling/dependencies"}
	}
	if strings.Contains(c, "test") || strings.Contains(c, "lint") || strings.Contains(c, "build") {
		return Assessment{Level: RiskLow, Category: RiskCommand, Reason: "benign test/lint/build command"}
	}
	return Assessment{Level: RiskLow, Category: RiskCommand, Reason: "general command execution"}
}

func ClassifyFilesystem(relPath string, op string, cfg *policy.Config) Assessment {
	p := filepath.ToSlash(strings.TrimPrefix(strings.TrimSpace(relPath), "./"))
	if p == "" {
		return Assessment{Level: RiskMedium, Category: RiskFilesystem, Reason: "unknown filesystem path"}
	}

	if touchesSensitivePath(p) {
		return Assessment{Level: RiskHigh, Category: RiskSecrets, Reason: "touches protected secret/auth path", HardBlocked: true}
	}

	if cfg != nil {
		dec := cfg.WriteDecision(p)
		if !dec.Allowed {
			return Assessment{Level: RiskHigh, Category: RiskFilesystem, Reason: "outside allowlist or deny rule matched", HardBlocked: true}
		}
	}

	if isRootConfigPath(p) {
		return Assessment{Level: RiskMedium, Category: RiskConfig, Reason: "writes root config file"}
	}
	if strings.Contains(strings.ToLower(p), "requirements.txt") || strings.Contains(strings.ToLower(p), "package-lock.json") {
		return Assessment{Level: RiskMedium, Category: RiskDependency, Reason: "dependency file change"}
	}
	if strings.EqualFold(op, "REMOVE") {
		return Assessment{Level: RiskMedium, Category: RiskFilesystem, Reason: "delete inside allowed zone"}
	}
	if strings.HasPrefix(p, "src/") || strings.HasPrefix(p, "app/") {
		return Assessment{Level: RiskLow, Category: RiskFilesystem, Reason: "write inside approved app path"}
	}

	return Assessment{Level: RiskMedium, Category: RiskFilesystem, Reason: "filesystem mutation outside app paths"}
}

func touchesSensitivePath(p string) bool {
	lp := strings.ToLower(p)
	return lp == ".env" || strings.HasPrefix(lp, ".env.") ||
		lp == ".ssh" || strings.HasPrefix(lp, ".ssh/") ||
		lp == ".aws" || strings.HasPrefix(lp, ".aws/") ||
		lp == ".git" || strings.HasPrefix(lp, ".git/") ||
		strings.Contains(lp, "deploy") ||
		strings.Contains(lp, "secret") ||
		strings.Contains(lp, "auth")
}

func isRootConfigPath(p string) bool {
	lp := strings.ToLower(p)
	if lp == ".github/workflows/ci.yml" || lp == ".github/workflows/ci.yaml" {
		return true
	}
	if strings.Contains(lp, "/") {
		return false
	}
	return lp == "package.json" ||
		lp == "pyproject.toml" ||
		lp == "dockerfile"
}
