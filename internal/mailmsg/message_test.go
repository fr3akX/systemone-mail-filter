package mailmsg

import (
	"bytes"
	"encoding/json"
	"mime"
	"strings"
	"testing"
)

func TestRewritePreservesMIMEAndUnrelatedHeaders(t *testing.T) {
	body := "--boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n--boundary\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=sample.bin\r\n\r\nAAECA/8=\r\n--boundary--\r\n"
	raw := []byte("From: sender@example.org\r\nSubject: =?UTF-8?B?0J/RgNC40LLQtdGC?=\r\nDKIM-Signature: v=1;\r\n\tb=unchanged\r\nX-sYsTeMoNe-Spam: No\r\nX-SystemOne-Other: forged\r\n folded\r\nContent-Type: multipart/mixed; boundary=boundary\r\n\r\n" + body)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	out := m.Rewrite("[SPAM]", true, []string{"X-SystemOne-Spam: Yes"})
	got, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, []byte(body)) {
		t.Fatal("MIME body changed")
	}
	if decodeHeader(got.Header.Get("Subject")) != "[SPAM] Привет" {
		t.Fatalf("subject: %q", got.Header.Get("Subject"))
	}
	if !bytes.Contains(out, []byte("DKIM-Signature: v=1;\r\n\tb=unchanged\r\n")) {
		t.Fatal("unrelated header changed")
	}
	if bytes.Contains(out, []byte("forged")) || bytes.Contains(out, []byte("folded")) {
		t.Fatal("forged filter header survived")
	}
	if got.Header.Get("X-SystemOne-Spam") != "Yes" {
		t.Fatal("missing verdict")
	}
	if second := got.Rewrite("[SPAM]", true, []string{"X-SystemOne-Spam: Yes"}); !bytes.Equal(out, second) {
		t.Fatal("tagging is not idempotent")
	}
	s, err := m.Extract("sender@example.org", 24000)
	if err != nil || len(s.Attachments) != 1 || s.Attachments[0].Filename != "sample.bin" || strings.Contains(s.Text, "AAECA") {
		t.Fatalf("attachment extraction: %#v %v", s, err)
	}
}

func TestSubjectVariants(t *testing.T) {
	for _, tc := range []struct{ name, subject, prefix, want string }{
		{"plain", "Subject: hello\r\n", "[SPAM]", "[SPAM] hello"},
		{"folded", "Subject: hello\r\n world\r\n", "[SPAM]", "[SPAM] hello world"},
		{"absent", "", "[SPAM]", "[SPAM]"},
		{"unicode prefix", "Subject: =?UTF-8?B?0J/RgNC40LLQtdGC?=\r\n", "[MĒSTULE]", "[MĒSTULE] Привет"},
		{"already encoded", "Subject: " + mime.QEncoding.Encode("utf-8", "[SPAM] Привет") + "\r\n", "[SPAM]", "[SPAM] Привет"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse([]byte("From: a@example.org\r\n" + tc.subject + "\r\nbody\r\n"))
			if err != nil {
				t.Fatal(err)
			}
			out, err := Parse(m.Rewrite(tc.prefix, true, nil))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(decodeHeader(out.Header.Get("Subject"))); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractHTMLCharsetAndBudget(t *testing.T) {
	raw := []byte("Subject: =?iso-8859-1?Q?caf=E9?=\nAuthentication-Results: forged; dkim=pass\nTo: private@example.net\nContent-Type: text/html; charset=iso-8859-1\nContent-Transfer-Encoding: quoted-printable\n\n<p>caf=E9 <a href=3D\"https://evil.example/login\">Trusted bank</a></p>\n" + strings.Repeat(strings.Repeat("x", 60)+"=\n", 170))
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Extract("bounce@example.org", 4096)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(s)
	if len(data) > 4096 || !s.Truncated {
		t.Fatalf("budget not enforced: %d", len(data))
	}
	if s.UntrustedHeader["subject"] != "café" || !strings.Contains(s.Text, "café") {
		t.Fatalf("charset not decoded: %#v", s)
	}
	if len(s.Links) != 1 || s.Links[0] != "https://evil.example/login" {
		t.Fatalf("links: %v", s.Links)
	}
	if bytes.Contains(data, []byte("private@example.net")) || bytes.Contains(data, []byte("dkim=pass")) {
		t.Fatal("unexpected private or untrusted authentication data")
	}
}

func TestHamSubjectIsBytePreserved(t *testing.T) {
	raw := []byte("Subject: =?UTF-8?B?0J/RgNC40LLQtdGC?=\r\n continuation\r\n\r\n.body\r\n")
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Rewrite("[SPAM]", false, nil); !bytes.Equal(got, raw) {
		t.Fatal("ham changed without diagnostics")
	}
}

func TestMalformedInput(t *testing.T) {
	for _, raw := range []string{"not a message", " broken\r\n\r\n", "Bad Header: value\r\n\r\n", "Subject: bad\rhidden: value\r\n\r\n"} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("accepted malformed headers %q", raw)
		}
	}
	for _, raw := range []string{
		"Subject: one\r\nSubject: two\r\n\r\nbody",
		"Content-Type: multipart/mixed\r\n\r\nbody",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!invalid!",
	} {
		m, err := Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Extract("", 4096); err == nil {
			t.Fatalf("accepted malformed MIME %q", raw)
		}
	}
}

func FuzzParseAndRewrite(f *testing.F) {
	f.Add([]byte("Subject: hello\r\n\r\nbody\r\n"))
	f.Add([]byte("Content-Type: multipart/mixed; boundary=x\n\n--x--\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1024*1024 {
			t.Skip()
		}
		m, err := Parse(raw)
		if err != nil {
			return
		}
		out := m.Rewrite("[SPAM]", false, []string{"X-SystemOne-Spam: Unknown"})
		m2, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(m.Body, m2.Body) {
			t.Fatal("body changed")
		}
		s, err := m.Extract("", 4096)
		if err == nil {
			data, _ := json.Marshal(s)
			if len(data) > 4096 {
				t.Fatal("state budget exceeded")
			}
		}
	})
}
