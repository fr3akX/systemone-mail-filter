package filter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/emersion/go-smtp"
	"golang.org/x/net/netutil"

	"github.com/fr3akX/systemone-mail-filter/internal/config"
)

type Recipient struct {
	Address string
	Options smtp.RcptOptions
}

type Envelope struct {
	From       string
	Options    smtp.MailOptions
	Recipients []Recipient
}

type Relay interface {
	Deliver(context.Context, Envelope, []byte) error
}

type SMTPRelay struct{ Config config.Config }

func (r SMTPRelay) Deliver(ctx context.Context, env Envelope, raw []byte) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", r.Config.Reinject)
	if err != nil {
		return errors.New("reinjection connection failed")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	c := smtp.NewClient(conn)
	defer c.Close()
	c.CommandTimeout = time.Duration(r.Config.SMTPTimeoutSeconds) * time.Second
	c.SubmissionTimeout = c.CommandTimeout
	if err := c.Hello(r.Config.Hostname); err != nil {
		return errors.New("reinjection greeting failed")
	}
	// The client library otherwise silently omits DSN options on unsupported peers.
	needsDSN := env.Options.Return != "" || env.Options.EnvelopeID != ""
	for _, to := range env.Recipients {
		needsDSN = needsDSN || len(to.Options.Notify) != 0 || to.Options.OriginalRecipient != ""
	}
	if ok, _ := c.Extension("DSN"); needsDSN && !ok {
		return errors.New("reinjection server lacks required DSN support")
	}
	opts := env.Options
	opts.Size = int64(len(raw))
	if err := c.Mail(env.From, &opts); err != nil {
		return errors.New("reinjection MAIL failed")
	}
	for _, to := range env.Recipients {
		if err := c.Rcpt(to.Address, &to.Options); err != nil {
			// No DATA has been sent, so retrying the whole envelope is safe.
			return errors.New("reinjection RCPT failed")
		}
	}
	w, err := c.Data()
	if err != nil {
		return errors.New("reinjection DATA failed")
	}
	if _, err := io.Copy(w, bytes.NewReader(raw)); err != nil {
		return errors.New("reinjection write failed")
	}
	if err := w.Close(); err != nil {
		return errors.New("reinjection final acknowledgement failed")
	}
	// DATA's 250 is the commit point. Do not turn a later QUIT error into a retry.
	return nil
}

type Backend struct {
	Processor *Processor
	Relay     Relay
	Log       *slog.Logger
}

func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	addr, ok := c.Conn().RemoteAddr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() {
		return nil, &smtp.SMTPError{Code: 554, Message: "local connections only"}
	}
	return &session{backend: b}, nil
}

type session struct {
	backend  *Backend
	envelope Envelope
}

func (s *session) Reset()        { s.envelope = Envelope{} }
func (s *session) Logout() error { return nil }
func (s *session) Mail(from string, opts *smtp.MailOptions) error {
	s.Reset()
	s.envelope.From = from
	if opts != nil {
		s.envelope.Options = *opts
	}
	return nil
}
func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	r := Recipient{Address: to}
	if opts != nil {
		r.Options = *opts
		r.Options.Notify = append([]smtp.DSNNotify(nil), opts.Notify...)
	}
	s.envelope.Recipients = append(s.envelope.Recipients, r)
	return nil
}
func temporary() error {
	return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "filter temporarily unavailable; message remains queued"}
}

func (s *session) Data(r io.Reader) error {
	started := time.Now()
	cfg := s.backend.Processor.Config
	raw, err := io.ReadAll(io.LimitReader(r, cfg.MaxMessageBytes+1))
	if err != nil || int64(len(raw)) > cfg.MaxMessageBytes {
		io.Copy(io.Discard, r)
		s.backend.Log.Error("message deferred", "error", "incomplete or oversized SMTP DATA")
		return temporary()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.SMTPTimeoutSeconds)*time.Second)
	defer cancel()
	out, report, err := s.backend.Processor.ProcessEnvelope(ctx, raw, s.envelope)
	if err == nil {
		err = s.backend.Relay.Deliver(ctx, s.envelope, out)
	}
	attrs := []any{"report", report, "recipients", len(s.envelope.Recipients), "bytes", len(raw), "duration_ms", time.Since(started).Milliseconds()}
	if err != nil {
		s.backend.Log.Error("message deferred", append(attrs, "error", err.Error())...)
		return temporary()
	}
	s.backend.Log.Info("message reinjected", attrs...)
	return nil
}

func NewServer(b *Backend) *smtp.Server {
	cfg := b.Processor.Config
	s := smtp.NewServer(b)
	s.Addr, s.Domain = cfg.Listen, cfg.Hostname
	s.MaxMessageBytes, s.MaxRecipients = cfg.MaxMessageBytes, cfg.MaxRecipients
	s.ReadTimeout = time.Duration(cfg.SMTPTimeoutSeconds) * time.Second
	s.WriteTimeout = s.ReadTimeout
	s.EnableSMTPUTF8, s.EnableDSN = true, true
	return s
}

func Serve(ctx context.Context, b *Backend) error {
	cfg := b.Processor.Config
	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer l.Close()
	s := NewServer(b)
	done := make(chan error, 1)
	go func() { done <- s.Serve(netutil.LimitListener(l, cfg.MaxConnections)) }()
	b.Log.Info("filter listening", "listen", cfg.Listen, "reinject", cfg.Reinject, "model", cfg.Model, "on_error", cfg.OnError)
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.SMTPTimeoutSeconds+5)*time.Second)
		defer cancel()
		if err := s.Shutdown(shutdown); err != nil {
			return err
		}
		// Also closes a listener if cancellation raced with Serve registering it.
		l.Close()
		return <-done
	}
}
