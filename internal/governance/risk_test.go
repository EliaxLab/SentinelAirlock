package governance

import (
	"testing"

	"github.com/EliaxLab/SentinelAirlock/internal/policy"
)

func cfgWith(allow, deny []string) *policy.Config {
	c := &policy.Config{}
	c.Policy.AllowWrite = allow
	c.Policy.DenyWrite = deny
	return c
}

// Legitimate deployment-style paths must reach normal policy evaluation: the
// built-in secret/auth classifier must not hard-block them merely because the
// word "deploy" appears as a substring.
func TestClassifyFilesystem_DeploymentStylePathsReachNormalPolicy(t *testing.T) {
	paths := []string{
		"k8s/deployment.yaml",
		"deployments/app.yaml",
		"scripts/redeploy.sh",
		"deploy/values.yaml",
		"src/deployment/config.yaml",
	}
	for _, p := range paths {
		t.Run(p+"/allowlisted", func(t *testing.T) {
			a := ClassifyFilesystem(p, "WRITE", cfgWith([]string{p}, nil))
			if a.HardBlocked || a.Category == RiskSecrets {
				t.Fatalf("%s was treated as a protected secret/auth path: %+v", p, a)
			}
			if d := Decide(ApprovalAuto, a); d != DecisionAllow {
				t.Fatalf("%s explicitly allowlisted but decision = %s (%+v)", p, d, a)
			}
		})
		t.Run(p+"/not-allowlisted-still-denied-by-policy", func(t *testing.T) {
			a := ClassifyFilesystem(p, "WRITE", cfgWith([]string{"src/other/**"}, nil))
			if !a.HardBlocked || a.Category != RiskFilesystem {
				t.Fatalf("%s outside the allowlist must be denied by normal policy, got %+v", p, a)
			}
		})
		t.Run(p+"/explicit-deny-still-denied", func(t *testing.T) {
			a := ClassifyFilesystem(p, "WRITE", cfgWith([]string{"**"}, []string{p}))
			if !a.HardBlocked || a.Category != RiskFilesystem {
				t.Fatalf("%s explicitly denied by policy must stay denied, got %+v", p, a)
			}
		})
	}
}

// Genuine secret/auth/credential paths keep their built-in hard block, even
// when the user's allowlist names them.
func TestClassifyFilesystem_GenuinelySensitivePathsStayProtected(t *testing.T) {
	paths := []string{
		".env", ".env.production",
		".ssh/id_rsa", ".aws/credentials", ".git/config",
		"config/secrets.yaml", "secrets/token.txt", "src/auth/login.go",
		"deploy_config.yaml", "prod/deploy_config.yaml",
		"deploy_key", "deploy.key", "deploy-token.txt", "deploy_credentials.json",
		"keys/deploy_keys/id_rsa", ".deploy_key", "deploykey.pem",
		"deploy.pem", "deploy_rsa", "deploy-ssh", "deploy.p12", "deploy.kubeconfig",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			a := ClassifyFilesystem(p, "WRITE", cfgWith([]string{"**"}, nil))
			if !a.HardBlocked || a.Category != RiskSecrets {
				t.Fatalf("%s must remain a protected secret/auth path, got %+v", p, a)
			}
		})
	}
}
