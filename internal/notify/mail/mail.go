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

type Message struct {
	From    string
	To      string
	Subject string
	Body    string
}

type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

type TLSMode string

const (
	TLSAuto     TLSMode = "auto"
	TLSNone     TLSMode = "none"
	TLSStartTLS TLSMode = "starttls"
	TLSImplicit TLSMode = "implicit"
)

type Config struct {
	Host     string  // SMTP relay hostname (e.g. "email-smtp.us-east-1.amazonaws.com")
	Port     int     // SMTP port (default 587)
	Username string  // PLAIN auth username; empty disables auth
	Password string  // PLAIN auth password
	From     string  // RFC5322 From header (e.g. "Concord <noreply@acme.test>")
	TLS      TLSMode // transport encryption mode (default TLSAuto)

	Timeout time.Duration
}

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

type SMTPMailer struct {
	cfg  Config
	dial dialer
}

type dialer func(ctx context.Context, cfg Config) (smtpSession, error)

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

type writer interface {
	Write([]byte) (int, error)
	Close() error
}

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

type realSession struct{ *smtp.Client }

func (r *realSession) Data() (writer, error) { return r.Client.Data() }

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

func buildRFC822(from string, msg Message) []byte {
	subject := msg.Subject
	if subject == "" {
		subject = "(no subject)"
	}
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
