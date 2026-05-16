// Package mail is the server's transactional-email surface. One Mailer
// interface, two concrete implementations:
//
//   - SMTPMailer relays messages through a configured SMTP server (SES,
//     SendGrid, Postmark, a self-hosted Postfix — anything that speaks
//     PLAIN auth + STARTTLS).
//   - LogMailer prints the message to slog instead of delivering it. This
//     is the dev-mode fallback used when CONCORD_SMTP_HOST is unset, so
//     a freshly-cloned `go run ./cmd/server` keeps working without
//     forcing every contributor to provision a relay.
//
// Mailer.Send is intentionally synchronous with a tight per-call timeout.
// Calling-site policy decides whether to fire-and-forget on a goroutine
// (recommended for password-reset, where SMTP latency must not slow the
// HTTP response) or block (recommended for tests).
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Message is one outbound email. From defaults to Config.From when empty
// so most callers don't have to set it.
type Message struct {
	From    string
	To      string
	Subject string
	Body    string
}

// Mailer is the contract every send path goes through. Implementations are
// safe for concurrent use unless their doc explicitly says otherwise.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// TLSMode controls SMTP transport encryption.
//
//	TLSAuto      use STARTTLS when the server advertises it; fall back to
//	             plaintext otherwise. The safe default — works with
//	             SES/SendGrid/Postmark on port 587.
//	TLSNone      always plaintext. ONLY for local-dev debug servers.
//	TLSStartTLS  always STARTTLS; error if the server doesn't advertise it.
//	TLSImplicit  implicit TLS (smtps, port 465) — wrap the dial socket in
//	             TLS from the first byte. Used by some legacy relays.
type TLSMode string

const (
	TLSAuto     TLSMode = "auto"
	TLSNone     TLSMode = "none"
	TLSStartTLS TLSMode = "starttls"
	TLSImplicit TLSMode = "implicit"
)

// Config is the construction surface. Host + From are the minimum to talk
// to a real relay; everything else has sensible defaults.
type Config struct {
	Host     string  // SMTP relay hostname (e.g. "email-smtp.us-east-1.amazonaws.com")
	Port     int     // SMTP port (default 587)
	Username string  // PLAIN auth username; empty disables auth
	Password string  // PLAIN auth password
	From     string  // RFC5322 From header (e.g. "Concord <noreply@acme.test>")
	TLS      TLSMode // transport encryption mode (default TLSAuto)

	// Timeout caps every send. Defaults to 10s — long enough for slow
	// relays, short enough that a wedged smtp server doesn't pile up
	// goroutines on a busy login endpoint.
	Timeout time.Duration
}

// New returns the Mailer matching cfg. If cfg.Host is empty, returns a
// LogMailer so dev environments don't require SMTP setup. The returned
// Mailer is safe for concurrent use.
func New(cfg Config) Mailer {
	if strings.TrimSpace(cfg.Host) == "" {
		slog.Info("mail: no SMTP host configured; outbound email will be logged instead of delivered")
		return &LogMailer{From: cfg.From}
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.TLS == "" {
		cfg.TLS = TLSAuto
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &SMTPMailer{cfg: cfg, dial: defaultDial}
}

// LogMailer is the no-SMTP fallback. Writes the message to slog at info
// level so a developer running `go run ./cmd/server` without an SMTP relay
// can still see exactly what would have been delivered (and click the
// embedded reset/invite URLs from the terminal).
type LogMailer struct {
	From string
}

func (m *LogMailer) Send(_ context.Context, msg Message) error {
	from := msg.From
	if from == "" {
		from = m.From
	}
	slog.Info("mail: would send (no SMTP configured)",
		slog.String("from", from),
		slog.String("to", msg.To),
		slog.String("subject", msg.Subject),
		slog.String("body", msg.Body))
	return nil
}

// SMTPMailer talks to a real SMTP relay. Construct via New(cfg). The dial
// field is the seam tests use to inject a fake client without spinning up
// a real listener; production callers never touch it.
type SMTPMailer struct {
	cfg  Config
	dial dialer
}

// dialer matches the subset of smtp.Client SMTPMailer.Send needs. Two
// implementations: defaultDial (the real net/smtp path) and the test
// helper that records calls.
type dialer func(ctx context.Context, cfg Config) (smtpSession, error)

// smtpSession is the subset of *smtp.Client SMTPMailer.Send drives. By
// expressing it as an interface, tests can inject a fake session that
// records the protocol exchange without a network listener.
type smtpSession interface {
	Hello(localName string) error
	StartTLS(config *tls.Config) error
	Auth(a smtp.Auth) error
	Mail(from string) error
	Rcpt(to string) error
	Data() (writer, error)
	Quit() error
	Close() error
	Extension(string) (bool, string)
}

// writer is the io.WriteCloser smtp.Client.Data() returns. Carved into its
// own type so the fake session can return a bytes.Buffer-shaped value.
type writer interface {
	Write([]byte) (int, error)
	Close() error
}

// defaultDial is the production smtp.Dial path.
func defaultDial(ctx context.Context, cfg Config) (smtpSession, error) {
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	var conn net.Conn
	d := net.Dialer{Timeout: cfg.Timeout}
	var err error
	if cfg.TLS == TLSImplicit {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: cfg.Host})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("smtp handshake: %w", err)
	}
	return &realSession{Client: c}, nil
}

// realSession adapts *smtp.Client to the smtpSession interface — the
// builtin methods almost match, except Data() returns io.WriteCloser
// which already satisfies our writer interface.
type realSession struct{ *smtp.Client }

func (r *realSession) Data() (writer, error) { return r.Client.Data() }

// Send composes the RFC822 message and pushes it through the configured
// relay. Errors are wrapped with context so an operator reading the log
// sees which leg of the conversation failed.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	if msg.To == "" {
		return errors.New("mail: To is required")
	}
	from := msg.From
	if from == "" {
		from = m.cfg.From
	}
	if from == "" {
		return errors.New("mail: From is required (set SMTP From in config or per-message)")
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return fmt.Errorf("mail: invalid From %q: %w", from, err)
	}
	to, err := mail.ParseAddress(msg.To)
	if err != nil {
		return fmt.Errorf("mail: invalid To %q: %w", msg.To, err)
	}

	sendCtx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()

	sess, err := m.dial(sendCtx, m.cfg)
	if err != nil {
		return err
	}
	defer sess.Close()

	if err := sess.Hello("concord"); err != nil {
		return fmt.Errorf("smtp HELO: %w", err)
	}

	// STARTTLS upgrade. TLSImplicit was already wrapped in defaultDial;
	// TLSStartTLS requires the server to advertise; TLSAuto opportunistic.
	switch m.cfg.TLS {
	case TLSStartTLS, TLSAuto:
		ok, _ := sess.Extension("STARTTLS")
		switch {
		case ok:
			if err := sess.StartTLS(&tls.Config{ServerName: m.cfg.Host}); err != nil {
				return fmt.Errorf("smtp STARTTLS: %w", err)
			}
		case m.cfg.TLS == TLSStartTLS:
			return errors.New("smtp: STARTTLS required but server did not advertise it")
		}
	}

	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := sess.Auth(auth); err != nil {
			return fmt.Errorf("smtp AUTH: %w", err)
		}
	}

	if err := sess.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := sess.Rcpt(to.Address); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := sess.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(buildRFC822(from, msg)); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp body write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp body close: %w", err)
	}
	if err := sess.Quit(); err != nil {
		return fmt.Errorf("smtp QUIT: %w", err)
	}
	return nil
}

// buildRFC822 produces the wire bytes the SMTP body carries — headers
// followed by CRLF then body. Subject/body go through 7-bit ASCII; for
// users whose names contain unicode we'd need quoted-printable encoding,
// not yet implemented (TODO when we have a non-ASCII customer).
func buildRFC822(from string, msg Message) []byte {
	subject := msg.Subject
	if subject == "" {
		subject = "(no subject)"
	}
	// Normalize CRLF line endings throughout the body — SMTP requires it,
	// and an embedded "\n.\n" would terminate the DATA section prematurely.
	body := strings.ReplaceAll(msg.Body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")

	var sb strings.Builder
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + msg.To + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	if !strings.HasSuffix(body, "\r\n") {
		sb.WriteString("\r\n")
	}
	return []byte(sb.String())
}
