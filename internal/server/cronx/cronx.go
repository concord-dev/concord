// Package cronx parses cron expressions for the scheduler and validates them
// up-front when handlers persist them. Standard 5-field syntax plus descriptors
// (@hourly, @every 5m, etc.) are accepted.
package cronx

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

// parser is created once; cron.Parser is stateless and safe to share.
var parser = cron.NewParser(
	cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
)

// Next returns the next fire time for the given expression, or an error
// explaining why the expression is unparseable.
func Next(expr string, from time.Time) (time.Time, error) {
	sched, err := parser.Parse(expr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid cron expression %q: %w", expr, err)
	}
	return sched.Next(from), nil
}
