package filter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/fr3akX/systemone-mail-filter/internal/config"
	"github.com/fr3akX/systemone-mail-filter/internal/jev"
	"github.com/fr3akX/systemone-mail-filter/internal/mailmsg"
)

type classifierFunc func(context.Context, mailmsg.State) (jev.Result, error)

func (f classifierFunc) Classify(ctx context.Context, s mailmsg.State) (jev.Result, error) {
	return f(ctx, s)
}

func classifier(spam float64, err error) jev.Classifier {
	return classifierFunc(func(context.Context, mailmsg.State) (jev.Result, error) {
		return jev.Result{Model: "test-model", SpamProbability: spam, Category: "correspondence", CategoryProbabilities: map[string]float64{"correspondence": 1}, Abuse: map[string]float64{"phishing": 0.9}}, err
	})
}

const message = "From: sender@example.org\r\nSubject: original\r\nX-SystemOne-Spam: forged\r\n\r\n.line one\r\nline two\r\n"

func TestProcessingPolicies(t *testing.T) {
	for _, tc := range []struct {
		name           string
		score          float64
		fail           bool
		policy         string
		status         string
		tag, deferMail bool
	}{
		{"ham", 0.1, false, "deliver_unmodified", "ham", false, false},
		{"spam at threshold", 0.95, false, "deliver_unmodified", "spam", true, false},
		{"fail open", 0, true, "deliver_unmodified", "unclassified", false, false},
		{"defer", 0, true, "defer", "unclassified", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.OnError = tc.policy
			cfg.SubjectPrefix = "[JUNK]"
			var apiErr error
			if tc.fail {
				apiErr = errors.New("test failure")
			}
			p := Processor{Config: cfg, Classifier: classifier(tc.score, apiErr)}
			out, report, err := p.Process(context.Background(), []byte(message), "sender@example.org")
			if (err != nil) != tc.deferMail || report.Status != tc.status || report.Tagged != tc.tag {
				t.Fatalf("report=%#v err=%v", report, err)
			}
			if tc.deferMail {
				return
			}
			m, err := mailmsg.Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			want := "original"
			if tc.tag {
				want = "[JUNK] original"
			}
			if m.Header.Get("Subject") != want {
				t.Fatalf("subject=%q", m.Header.Get("Subject"))
			}
			if bytes.Contains(out, []byte("forged")) {
				t.Fatal("forged verdict remains")
			}
			if string(m.Body) != ".line one\r\nline two\r\n" {
				t.Fatal("body changed")
			}
		})
	}
}

type received struct {
	envelope Envelope
	raw      []byte
}
type sink struct {
	mail            chan received
	rejectRecipient string
	failData        bool
	attempts        atomic.Int32
}

func (s *sink) NewSession(*smtp.Conn) (smtp.Session, error) { return &sinkSession{sink: s}, nil }

type sinkSession struct {
	sink *sink
	env  Envelope
}

func (s *sinkSession) Reset()        { s.env = Envelope{} }
func (s *sinkSession) Logout() error { return nil }
func (s *sinkSession) Mail(from string, opts *smtp.MailOptions) error {
	s.env = Envelope{From: from, Options: *opts}
	return nil
}
func (s *sinkSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	if to == s.sink.rejectRecipient {
		return &smtp.SMTPError{Code: 550, Message: "synthetic recipient failure"}
	}
	s.env.Recipients = append(s.env.Recipients, Recipient{to, *opts})
	return nil
}
func (s *sinkSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.sink.attempts.Add(1)
	if s.sink.failData {
		return &smtp.SMTPError{Code: 451, Message: "synthetic queue failure"}
	}
	s.sink.mail <- received{s.env, raw}
	return nil
}

func startServer(t *testing.T, b smtp.Backend, dsn bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(b)
	srv.Domain = "test.local"
	srv.EnableDSN = dsn
	srv.EnableSMTPUTF8 = true
	srv.ReadTimeout = 5 * time.Second
	srv.WriteTimeout = 5 * time.Second
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l.Addr().String()
}

func submit(addr string, env Envelope) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cfg := config.Default()
	cfg.Reinject = addr
	return (SMTPRelay{cfg}).Deliver(ctx, env, []byte(message))
}

func TestSMTPPreservesEnvelopeAndWaitsForReinjection(t *testing.T) {
	sink := &sink{mail: make(chan received, 1)}
	destination := startServer(t, sink, true)
	cfg := config.Default()
	cfg.Reinject = destination
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	b := &Backend{Processor: &Processor{Config: cfg, Classifier: classifier(0.99, nil)}, Relay: SMTPRelay{cfg}, Log: log}
	addr := startServer(t, b, true)
	env := Envelope{From: "", Options: smtp.MailOptions{UTF8: true, Return: smtp.DSNReturnHeaders, EnvelopeID: "original-envelope"}, Recipients: []Recipient{
		{Address: "first@example.net", Options: smtp.RcptOptions{Notify: []smtp.DSNNotify{smtp.DSNNotifyFailure}, OriginalRecipientType: smtp.DSNAddressTypeRFC822, OriginalRecipient: "alias@example.net"}},
		{Address: "otrs@example.net"},
	}}
	if err := submit(addr, env); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sink.mail:
		if got.envelope.From != "" || len(got.envelope.Recipients) != 2 || !got.envelope.Options.UTF8 || got.envelope.Options.EnvelopeID != "original-envelope" || got.envelope.Options.Return != smtp.DSNReturnHeaders {
			t.Fatalf("envelope changed: %#v", got.envelope)
		}
		rcpt := got.envelope.Recipients[0]
		if rcpt.Options.OriginalRecipient != "alias@example.net" || len(rcpt.Options.Notify) != 1 || rcpt.Options.Notify[0] != smtp.DSNNotifyFailure {
			t.Fatalf("DSN lost: %#v", rcpt)
		}
		m, err := mailmsg.Parse(got.raw)
		if err != nil {
			t.Fatal(err)
		}
		if m.Header.Get("Subject") != "[SPAM] original" || string(m.Body) != ".line one\r\nline two\r\n" {
			t.Fatalf("message changed unexpectedly: %q", got.raw)
		}
	default:
		t.Fatal("filter acknowledged before reinjection")
	}
}

func TestSMTPFailuresRemainTemporary(t *testing.T) {
	for _, tc := range []struct {
		name, policy                string
		apiFail, rcptFail, dataFail bool
	}{
		{"classification", "defer", true, false, false},
		{"partial recipient failure", "deliver_unmodified", false, true, false},
		{"queue failure", "deliver_unmodified", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &sink{mail: make(chan received, 1), failData: tc.dataFail}
			if tc.rcptFail {
				sink.rejectRecipient = "second@example.net"
			}
			cfg := config.Default()
			cfg.Reinject = startServer(t, sink, true)
			cfg.OnError = tc.policy
			var apiErr error
			if tc.apiFail {
				apiErr = errors.New("synthetic API failure")
			}
			b := &Backend{Processor: &Processor{Config: cfg, Classifier: classifier(0.99, apiErr)}, Relay: SMTPRelay{cfg}, Log: slog.New(slog.NewJSONHandler(io.Discard, nil))}
			addr := startServer(t, b, true)
			c, err := smtp.Dial(addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.Mail("sender@example.org", nil); err != nil {
				t.Fatal(err)
			}
			for _, to := range []string{"first@example.net", "second@example.net"} {
				if err := c.Rcpt(to, nil); err != nil {
					t.Fatal(err)
				}
			}
			w, err := c.Data()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(w, message); err != nil {
				t.Fatal(err)
			}
			err = w.Close()
			var smtpErr *smtp.SMTPError
			if !errors.As(err, &smtpErr) || smtpErr.Code != 451 {
				t.Fatalf("expected temporary 451, got %v", err)
			}
			if len(sink.mail) != 0 {
				t.Fatal("message incorrectly accepted")
			}
			if !tc.dataFail && sink.attempts.Load() != 0 {
				t.Fatal("DATA sent despite earlier failure")
			}
		})
	}
}

func TestRelayRequiresDSNSupport(t *testing.T) {
	sink := &sink{mail: make(chan received, 1)}
	addr := startServer(t, sink, false)
	err := submit(addr, Envelope{From: "sender@example.org", Options: smtp.MailOptions{EnvelopeID: "keep-me"}, Recipients: []Recipient{{Address: "recipient@example.net"}}})
	if err == nil || !strings.Contains(err.Error(), "DSN") || sink.attempts.Load() != 0 {
		t.Fatalf("silently dropped DSN: %v", err)
	}
}

func TestRelayTotalDeadline(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	cfg := config.Default()
	cfg.Reinject = l.Addr().String()
	if err := (SMTPRelay{cfg}).Deliver(ctx, Envelope{}, []byte(message)); err == nil {
		t.Fatal("stalled SMTP connection succeeded")
	}
	<-done
}
