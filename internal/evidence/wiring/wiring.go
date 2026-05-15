// Package wiring assembles an evidence.Registry from the process environment.
// One place for the "which collectors get plugged in?" decision logic so that
// `concord check`, `concord doctor`, and `concord-server` all auto-detect the
// same way.
//
// Detection rules per provider:
//
//	github       CONCORD_GITHUB_TOKEN or GITHUB_TOKEN
//	aws          AWS_ACCESS_KEY_ID | AWS_PROFILE | AWS_ROLE_ARN |
//	             AWS_WEB_IDENTITY_TOKEN_FILE | ~/.aws/credentials present
//	mlflow       MLFLOW_TRACKING_URI (MLFLOW_TRACKING_TOKEN optional)
//	okta         OKTA_ORG_URL AND OKTA_API_TOKEN both present
//	snyk         SNYK_TOKEN
//	wandb        WANDB_API_KEY (WANDB_BASE_URL optional)
//	huggingface  always registered; HUGGINGFACE_TOKEN optional (private repos)
//
// The huggingface exception is intentional: the public Hub serves anonymous
// reads, so we can usefully evaluate HF controls even with zero env setup.
package wiring

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/concord-dev/concord/internal/evidence"
	awsev "github.com/concord-dev/concord/internal/evidence/aws"
	ghev "github.com/concord-dev/concord/internal/evidence/github"
	hfev "github.com/concord-dev/concord/internal/evidence/huggingface"
	mlflowev "github.com/concord-dev/concord/internal/evidence/mlflow"
	oktaev "github.com/concord-dev/concord/internal/evidence/okta"
	snykev "github.com/concord-dev/concord/internal/evidence/snyk"
	wandbev "github.com/concord-dev/concord/internal/evidence/wandb"
)

// BuildRegistry assembles a Registry from the process env. When fixturesOnly
// is true the Registry is forced into fixture-only mode and no live collector
// is registered. Otherwise we wire whatever credentials are present.
//
// warn is where soft warnings (e.g. AWS detected but config load failed) get
// written. Pass io.Discard to silence; pass os.Stderr to surface them in
// production. nil is treated as io.Discard.
func BuildRegistry(ctx context.Context, fixturesOnly bool, warn io.Writer) *evidence.Registry {
	reg := evidence.NewRegistry()
	if fixturesOnly {
		reg.SetFixturesOnly(true)
		return reg
	}
	if warn == nil {
		warn = io.Discard
	}

	if tok := GitHubToken(); tok != "" {
		reg.Register("github", ghev.New(tok))
	}
	if HasAWSCredentials() {
		if c, err := awsev.New(ctx, os.Getenv("AWS_REGION")); err == nil {
			reg.Register("aws", c)
		} else {
			fmt.Fprintln(warn, "warning: AWS credentials detected but config load failed:", err)
		}
	}
	if uri := os.Getenv("MLFLOW_TRACKING_URI"); uri != "" {
		reg.Register("mlflow", mlflowev.New(uri, os.Getenv("MLFLOW_TRACKING_TOKEN")))
	}
	if org, tok := os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_API_TOKEN"); org != "" && tok != "" {
		reg.Register("okta", oktaev.New(org, tok))
	}
	if tok := os.Getenv("SNYK_TOKEN"); tok != "" {
		reg.Register("snyk", snykev.New(tok))
	}
	if key := os.Getenv("WANDB_API_KEY"); key != "" {
		reg.Register("wandb", wandbev.New(os.Getenv("WANDB_BASE_URL"), key))
	}
	reg.Register("huggingface", hfev.New(os.Getenv("HUGGINGFACE_BASE_URL"), os.Getenv("HUGGINGFACE_TOKEN")))
	return reg
}

// GitHubToken returns the first non-empty of CONCORD_GITHUB_TOKEN or GITHUB_TOKEN.
// Exported so `concord doctor` can probe with the same lookup rule.
func GitHubToken() string {
	if t := os.Getenv("CONCORD_GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GITHUB_TOKEN")
}

// HasAWSCredentials reports whether any AWS SDK lookup path is populated:
// env vars (AWS_ACCESS_KEY_ID, AWS_PROFILE, AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE)
// or a credentials file at ~/.aws/credentials. We don't probe IMDS — that's a
// network call and `doctor` already separates "credentials present" from
// "credentials work."
func HasAWSCredentials() bool {
	for _, e := range []string{"AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
		if os.Getenv(e) != "" {
			return true
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".aws", "credentials")); err == nil {
			return true
		}
	}
	return false
}
