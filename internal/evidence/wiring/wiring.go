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

func GitHubToken() string {
	if t := os.Getenv("CONCORD_GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GITHUB_TOKEN")
}

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
