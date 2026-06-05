package server

import (
	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/server/handlers/auth"
	"github.com/concord-dev/concord/internal/server/handlers/public"
)

func (c *Concord) SetLimitsForTest(a auth.Limits, p public.Limits) {
	c.authLimits = a
	c.pubLimits = p
}

func (c *Concord) SetMailerForTest(m mail.Mailer) {
	c.mailer = m
}
