package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestNew_ReturnsLogMailerWhenHostEmpty(t *testing.T) {
	m := New(Config{From: "noreply@example.com"})
	_, ok := m.(*LogMailer)
	assert.True(t, ok,
		"empty Host must short-circuit to LogMailer — that's the dev-friendly fallback")
}

func TestLogMailer_SendIsAlwaysSuccess(t *testing.T) {
	m := &LogMailer{From: "noreply@example.com"}
	err := m.Send(context.Background(), Message{
		To: "u@example.com", Subject: "hi", Body: "ok",
	})
	assert.NoError(t, err)
}


func TestBuildRFC822_HasCanonicalHeadersAndCRLFLines(t *testing.T) {
	body := buildRFC822("noreply@example.com", Message{
		To: "u@example.com", Subject: "hello", Body: "line1\nline2",
	})
	s := string(body)
	assert.Contains(t, s, "From: noreply@example.com\r\n")
	assert.Contains(t, s, "To: u@example.com\r\n")
	assert.Contains(t, s, "Subject: hello\r\n")
	assert.Contains(t, s, "MIME-Version: 1.0\r\n")
	assert.Contains(t, s, "Content-Type: text/plain; charset=utf-8\r\n")
	assert.Contains(t, s, "line1\r\nline2\r\n")
	assert.NotContains(t, s, "line1\nline2",
		"any bare LF in the wire bytes is a protocol violation waiting to happen")
}

func TestBuildRFC822_DefaultsEmptySubject(t *testing.T) {
	body := string(buildRFC822("a@example.com", Message{To: "b@example.com", Body: "x"}))
	assert.Contains(t, body, "Subject: (no subject)\r\n")
}


type fakeSession struct {
	verbs        []string
	bodyBytes    []byte
	starttlsAdvertised bool
	failOn       string // verb name to fail on, e.g. "RCPT"
}

func (f *fakeSession) record(v string) error {
	f.verbs = append(f.verbs, v)
	if f.failOn == v {
		return fmt.Errorf("forced failure on %s", v)
	}
	return nil
}
func (f *fakeSession) Hello(string) error            { return f.record("HELO") }
func (f *fakeSession) Extension(name string) (bool, string) {
	if name == "STARTTLS" {
		return f.starttlsAdvertised, ""
	}
	return false, ""
}
func (*fakeSession) StartTLS(*tls.Config) error      { return nil }
func (f *fakeSession) Auth(a smtp.Auth) error        { return f.record("AUTH") }
func (f *fakeSession) Mail(string) error             { return f.record("MAIL") }
func (f *fakeSession) Rcpt(string) error             { return f.record("RCPT") }
func (f *fakeSession) Data() (writer, error)        {
	if err := f.record("DATA"); err != nil {
		return nil, err
	}
	return &captureWriter{f: f}, nil
}
func (f *fakeSession) Quit() error                   { return f.record("QUIT") }
func (f *fakeSession) Close() error                  { return nil }

type captureWriter struct{ f *fakeSession }

func (c *captureWriter) Write(p []byte) (int, error) {
	c.f.bodyBytes = append(c.f.bodyBytes, p...)
	return len(p), nil
}
func (c *captureWriter) Close() error { return nil }

func TestSMTPMailer_DrivesProtocolInTheRightOrder(t *testing.T) {
	fs := &fakeSession{}
	m := &SMTPMailer{
		cfg: Config{Host: "smtp.test", Port: 587, From: "noreply@example.com", TLS: TLSNone, Timeout: time.Second},
		dial: func(context.Context, Config) (smtpSession, error) { return fs, nil },
	}
	err := m.Send(context.Background(), Message{
		To: "user@example.com", Subject: "hi", Body: "hello",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"HELO", "MAIL", "RCPT", "DATA", "QUIT"}, fs.verbs)
	assert.Contains(t, string(fs.bodyBytes), "Subject: hi\r\n")
	assert.Contains(t, string(fs.bodyBytes), "hello\r\n")
}

func TestSMTPMailer_AuthsWhenUsernameSet(t *testing.T) {
	fs := &fakeSession{}
	m := &SMTPMailer{
		cfg: Config{Host: "smtp.test", Port: 587, Username: "u", Password: "p", From: "n@example.com", TLS: TLSNone, Timeout: time.Second},
		dial: func(context.Context, Config) (smtpSession, error) { return fs, nil },
	}
	require.NoError(t, m.Send(context.Background(), Message{To: "u@example.com", Body: "x"}))
	assert.Contains(t, fs.verbs, "AUTH",
		"PLAIN auth must run when Username is set — otherwise SES rejects with 530")
}

func TestSMTPMailer_StartTLSRequiredErrorsWhenServerDoesNotAdvertise(t *testing.T) {
	fs := &fakeSession{starttlsAdvertised: false}
	m := &SMTPMailer{
		cfg: Config{Host: "smtp.test", Port: 587, From: "n@example.com", TLS: TLSStartTLS, Timeout: time.Second},
		dial: func(context.Context, Config) (smtpSession, error) { return fs, nil },
	}
	err := m.Send(context.Background(), Message{To: "u@example.com", Body: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "STARTTLS required",
		"refusing to fall back to plaintext when TLSStartTLS was explicitly chosen is the whole point of the setting")
}

func TestSMTPMailer_RejectsInvalidAddresses(t *testing.T) {
	m := &SMTPMailer{cfg: Config{Host: "smtp.test", From: "n@example.com", Timeout: time.Second},
		dial: func(context.Context, Config) (smtpSession, error) { return &fakeSession{}, nil }}
	cases := []struct {
		name string
		msg  Message
	}{
		{"empty To", Message{Body: "x"}},
		{"malformed To", Message{To: "not-an-email", Body: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.Send(context.Background(), tc.msg)
			assert.Error(t, err)
		})
	}
}


func startFakeSMTP(t *testing.T) (host string, port int, recvd <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	bodies := []string{}
	ch := make(chan string, 1)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSMTPConn(conn, &mu, &bodies, ch)
		}
	}()
	hostPort := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", hostPort.Port, ch
}

func handleSMTPConn(conn net.Conn, mu *sync.Mutex, bodies *[]string, ch chan<- string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	writeLine := func(s string) {
		_, _ = io.WriteString(conn, s+"\r\n")
	}
	writeLine("220 fake.smtp ready")

	inData := false
	var dataBuf strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				mu.Lock()
				*bodies = append(*bodies, dataBuf.String())
				select {
				case ch <- dataBuf.String():
				default:
				}
				mu.Unlock()
				writeLine("250 OK")
				continue
			}
			dataBuf.WriteString(line + "\n")
			continue
		}
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			writeLine("250-fake.smtp")
			writeLine("250 OK")
		case strings.HasPrefix(up, "MAIL FROM"), strings.HasPrefix(up, "RCPT TO"):
			writeLine("250 OK")
		case up == "DATA":
			writeLine("354 send body, end with .")
			inData = true
		case up == "QUIT":
			writeLine("221 bye")
			return
		default:
			writeLine("250 OK")
		}
	}
}

func TestSMTPMailer_EndToEndAgainstFakeListener(t *testing.T) {
	host, port, recvd := startFakeSMTP(t)
	m := New(Config{
		Host: host, Port: port,
		From:    "Concord <noreply@example.com>",
		TLS:     TLSNone,
		Timeout: 3 * time.Second,
	})
	err := m.Send(context.Background(), Message{
		To: "user@example.com", Subject: "drift on iam-no-root-keys",
		Body: "Run 42 regressed:\n  pass → fail",
	})
	require.NoError(t, err)

	select {
	case body := <-recvd:
		assert.Contains(t, body, "Subject: drift on iam-no-root-keys")
		assert.Contains(t, body, "Concord <noreply@example.com>")
		assert.Contains(t, body, "pass → fail")
	case <-time.After(3 * time.Second):
		t.Fatal("fake SMTP did not receive the message body within 3s")
	}
}
