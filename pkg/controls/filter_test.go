package controls

import (
	"testing"

	"github.com/stretchr/testify/assert"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func loaded(id, framework, severity string, tags ...string) Loaded {
	return Loaded{Control: apiv1.Control{Metadata: apiv1.ControlMetadata{
		ID: id, Framework: framework, Severity: severity, Tags: tags,
	}}}
}

func TestFilter_Empty_PassesThrough(t *testing.T) {
	in := []Loaded{loaded("a", "gdpr", "high"), loaded("b", "soc2", "low")}
	assert.Equal(t, in, Filter{}.Apply(in))
}

func TestFilter_Framework(t *testing.T) {
	in := []Loaded{loaded("a", "gdpr", "high"), loaded("b", "soc2", "low")}
	out := Filter{Frameworks: []string{"gdpr"}}.Apply(in)
	assert.Len(t, out, 1)
	assert.Equal(t, "a", out[0].Control.Metadata.ID)
}

func TestFilter_FrameworkCaseInsensitive(t *testing.T) {
	in := []Loaded{loaded("a", "GDPR", "high")}
	out := Filter{Frameworks: []string{"gdpr"}}.Apply(in)
	assert.Len(t, out, 1)
}

func TestFilter_Severity(t *testing.T) {
	in := []Loaded{loaded("a", "gdpr", "high"), loaded("b", "gdpr", "low")}
	out := Filter{Severities: []string{"high"}}.Apply(in)
	assert.Len(t, out, 1)
	assert.Equal(t, "a", out[0].Control.Metadata.ID)
}

func TestFilter_Tag_AnyMatchPasses(t *testing.T) {
	in := []Loaded{loaded("a", "gdpr", "high", "iam", "data"), loaded("b", "gdpr", "high", "network")}
	out := Filter{Tags: []string{"iam"}}.Apply(in)
	assert.Len(t, out, 1)
	assert.Equal(t, "a", out[0].Control.Metadata.ID)
}

func TestFilter_ID(t *testing.T) {
	in := []Loaded{loaded("a", "gdpr", "high"), loaded("b", "gdpr", "high")}
	out := Filter{IDs: []string{"b"}}.Apply(in)
	assert.Len(t, out, 1)
	assert.Equal(t, "b", out[0].Control.Metadata.ID)
}

func TestFilter_AxesIntersect(t *testing.T) {
	in := []Loaded{
		loaded("a", "gdpr", "high"),
		loaded("b", "soc2", "high"),
		loaded("c", "gdpr", "low"),
	}
	out := Filter{Frameworks: []string{"gdpr"}, Severities: []string{"high"}}.Apply(in)
	assert.Len(t, out, 1)
	assert.Equal(t, "a", out[0].Control.Metadata.ID)
}

func TestFilter_IgnoresEmptyStrings(t *testing.T) {
	in := []Loaded{loaded("a", "gdpr", "high")}
	out := Filter{Frameworks: []string{"", "gdpr", ""}}.Apply(in)
	assert.Len(t, out, 1)
}
