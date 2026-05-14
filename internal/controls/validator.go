package controls

import (
	"errors"
	"fmt"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Validate checks that a control has the minimum required fields.
func Validate(c apiv1.Control) error {
	var errs []error

	if c.APIVersion == "" {
		errs = append(errs, errors.New("apiVersion is required"))
	}
	if c.Kind != "Control" {
		errs = append(errs, fmt.Errorf("kind must be %q, got %q", "Control", c.Kind))
	}
	if c.Metadata.ID == "" {
		errs = append(errs, errors.New("metadata.id is required"))
	}
	if c.Metadata.Title == "" {
		errs = append(errs, errors.New("metadata.title is required"))
	}
	if c.Metadata.Framework == "" {
		errs = append(errs, errors.New("metadata.framework is required"))
	}
	if !validSeverity(c.Metadata.Severity) {
		errs = append(errs, fmt.Errorf("metadata.severity %q is not one of critical|high|medium|low|info", c.Metadata.Severity))
	}
	if c.Spec.Description == "" {
		errs = append(errs, errors.New("spec.description is required"))
	}
	if len(c.Spec.Evidence) == 0 {
		errs = append(errs, errors.New("spec.evidence must have at least one entry"))
	}
	if c.Spec.Policy.File == "" {
		errs = append(errs, errors.New("spec.policy.file is required"))
	}
	if c.Spec.Policy.Package == "" {
		errs = append(errs, errors.New("spec.policy.package is required"))
	}

	for i, e := range c.Spec.Evidence {
		if e.ID == "" {
			errs = append(errs, fmt.Errorf("evidence[%d].id is required", i))
		}
		if e.Source == "" {
			errs = append(errs, fmt.Errorf("evidence[%d].source is required", i))
		}
	}

	return errors.Join(errs...)
}

func validSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}
