// Package mailmsg extracts bounded classification input while retaining the
// original message bytes for delivery. It never serializes a parsed MIME tree.
package mailmsg

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

type Field struct {
	Name string
	Raw  []byte // Includes original folding and final newline.
}

type Message struct {
	Fields  []Field
	Header  mail.Header
	Body    []byte
	Newline string
}

func Parse(raw []byte) (*Message, error) {
	// Find the first empty line, accepting CRLF or LF input without touching body bytes.
	offset, end := 0, -1
	m := &Message{Newline: "\r\n"}
	for offset < len(raw) {
		n := bytes.IndexByte(raw[offset:], '\n')
		if n < 0 {
			break
		}
		next := offset + n + 1
		line := bytes.TrimSuffix(raw[offset:next-1], []byte{'\r'})
		if next > 256*1024 {
			return nil, errors.New("headers exceed 256KiB")
		}
		if len(line) == 0 {
			end = next
			if next-offset == 1 {
				m.Newline = "\n"
			}
			break
		}
		if bytes.ContainsRune(line, '\r') || bytes.ContainsRune(line, 0) {
			return nil, errors.New("invalid header control character")
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(m.Fields) == 0 {
				return nil, errors.New("header continuation without field")
			}
			i := len(m.Fields) - 1
			m.Fields[i].Raw = append(m.Fields[i].Raw, raw[offset:next]...)
		} else {
			colon := bytes.IndexByte(line, ':')
			if colon < 1 {
				return nil, errors.New("invalid header field")
			}
			for _, c := range line[:colon] {
				if c < 33 || c > 126 {
					return nil, errors.New("invalid header name")
				}
			}
			m.Fields = append(m.Fields, Field{Name: string(line[:colon]), Raw: bytes.Clone(raw[offset:next])})
		}
		offset = next
	}
	if end < 0 {
		return nil, errors.New("missing header/body separator")
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(raw[:end]))
	if err != nil {
		return nil, errors.New("invalid message headers")
	}
	m.Header, m.Body = parsed.Header, raw[end:]
	return m, nil
}

var wordDecoder = mime.WordDecoder{CharsetReader: charset.NewReaderLabel}

func decodeHeader(s string) string {
	decoded, err := wordDecoder.DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}

func clip(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

type Attachment struct {
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"content_type"`
}

type State struct {
	EnvelopeFrom    string            `json:"envelope_from"`
	UntrustedHeader map[string]string `json:"untrusted_headers"`
	Text            string            `json:"text"`
	Links           []string          `json:"links,omitempty"`
	Attachments     []Attachment      `json:"attachments,omitempty"`
	Truncated       bool              `json:"truncated"`
}

// Extract deliberately excludes recipient addresses and Authentication-Results:
// arbitrary incoming headers are not evidence of locally verified authentication.
func (m *Message) Extract(from string, limit int) (State, error) {
	s := State{EnvelopeFrom: clip(from, 512), UntrustedHeader: make(map[string]string)}
	if len(m.Header["Subject"]) > 1 {
		return s, errors.New("multiple Subject fields")
	}
	for _, name := range []string{"Subject", "From", "Reply-To", "List-Id", "List-Unsubscribe"} {
		value := decodeHeader(m.Header.Get(name))
		s.UntrustedHeader[strings.ToLower(name)] = clip(value, 1024)
		if len(value) > 1024 {
			s.Truncated = true
		}
	}
	e := extractor{state: &s, remaining: limit, parts: 128}
	if err := e.part(textproto.MIMEHeader(m.Header), bytes.NewReader(m.Body), 0); err != nil {
		return s, err
	}
	// Enforce the budget on serialized JSON too (escaping can expand strings).
	for {
		data, err := json.Marshal(s)
		if err != nil {
			return s, err
		}
		if len(data) <= limit {
			break
		}
		s.Truncated = true
		switch {
		case len(s.Text) > 512:
			s.Text = clip(s.Text, len(s.Text)*3/4)
		case len(s.Links) > 0:
			s.Links = s.Links[:len(s.Links)-1]
		case len(s.Attachments) > 0:
			s.Attachments = s.Attachments[:len(s.Attachments)-1]
		default:
			for k, v := range s.UntrustedHeader {
				s.UntrustedHeader[k] = clip(v, len(v)/2)
			}
			s.EnvelopeFrom = clip(s.EnvelopeFrom, len(s.EnvelopeFrom)/2)
			s.Text = clip(s.Text, len(s.Text)/2)
		}
	}
	return s, nil
}

type extractor struct {
	state     *State
	remaining int
	parts     int
}

func (e *extractor) part(h textproto.MIMEHeader, r io.Reader, depth int) error {
	e.parts--
	if depth > 16 || e.parts < 0 {
		return errors.New("MIME nesting or part limit exceeded")
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=us-ascii"
	}
	media, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return errors.New("invalid MIME content type")
	}
	disp, dp, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	filename := dp["filename"]
	if filename == "" {
		filename = params["name"]
	}
	if disp == "attachment" || filename != "" || (!strings.HasPrefix(media, "multipart/") && media != "text/plain" && media != "text/html") {
		if len(e.state.Attachments) < 32 {
			e.state.Attachments = append(e.state.Attachments, Attachment{clip(decodeHeader(filename), 256), clip(media, 128)})
		} else {
			e.state.Truncated = true
		}
		return nil
	}
	if strings.HasPrefix(media, "multipart/") {
		if params["boundary"] == "" {
			return errors.New("missing MIME boundary")
		}
		mr := multipart.NewReader(r, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return errors.New("invalid MIME multipart")
			}
			err = e.part(p.Header, p, depth+1)
			p.Close()
			if err != nil {
				return err
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "", "7bit", "8bit", "binary":
	default:
		return errors.New("unsupported MIME transfer encoding")
	}
	if cs := params["charset"]; cs != "" && !strings.EqualFold(cs, "utf-8") {
		r, err = charset.NewReaderLabel(cs, r)
		if err != nil {
			return errors.New("unsupported text charset")
		}
	}
	data, err := io.ReadAll(io.LimitReader(r, int64(e.remaining)+1))
	if err != nil {
		return errors.New("invalid MIME text encoding")
	}
	if len(data) > e.remaining {
		data = data[:e.remaining]
		e.state.Truncated = true
	}
	e.remaining -= len(data)
	text := strings.ToValidUTF8(string(data), "\uFFFD")
	if media == "text/html" {
		var b strings.Builder
		z := html.NewTokenizer(strings.NewReader(text))
		for {
			t := z.Next()
			if t == html.ErrorToken {
				break
			}
			switch t {
			case html.TextToken:
				b.WriteString(string(z.Text()))
				b.WriteByte(' ')
			case html.StartTagToken, html.SelfClosingTagToken:
				token := z.Token()
				for _, a := range token.Attr {
					if a.Key == "href" || a.Key == "src" || a.Key == "action" {
						e.link(a.Val)
					}
				}
			}
		}
		text = b.String()
	}
	for _, link := range urlPattern.FindAllString(text, 32) {
		e.link(link)
	}
	if text != "" {
		e.state.Text += "\n" + text
	}
	return nil
}

var urlPattern = regexp.MustCompile(`https?://[^\s<>"']+`)

func (e *extractor) link(s string) {
	if len(e.state.Links) >= 32 {
		e.state.Truncated = true
		return
	}
	s = clip(s, 512)
	for _, old := range e.state.Links {
		if old == s {
			return
		}
	}
	e.state.Links = append(e.state.Links, s)
}

// Rewrite replaces only our namespace and (when needed) the Subject. All other
// header fields and the complete MIME body retain their original bytes.
func (m *Message) Rewrite(prefix string, tag bool, diagnostics []string) []byte {
	var out bytes.Buffer
	hasSubject := false
	for _, f := range m.Fields {
		if strings.HasPrefix(strings.ToLower(f.Name), "x-systemone-") {
			continue
		}
		if tag && strings.EqualFold(f.Name, "Subject") {
			hasSubject = true
			value := strings.TrimSpace(decodeHeader(m.Header.Get("Subject")))
			if !strings.HasPrefix(value, prefix) {
				encoded := mime.QEncoding.Encode("utf-8", prefix)
				if encoded != prefix {
					encoded = mime.QEncoding.Encode("utf-8", prefix+" ")
				}
				colon := bytes.IndexByte(f.Raw, ':')
				original := bytes.TrimLeft(f.Raw[colon+1:], " \t")
				fmt.Fprintf(&out, "Subject: %s%s %s", encoded, m.Newline, original)
				continue
			}
		}
		out.Write(f.Raw)
	}
	if tag && !hasSubject {
		fmt.Fprintf(&out, "Subject: %s%s", mime.QEncoding.Encode("utf-8", prefix), m.Newline)
	}
	for _, h := range diagnostics {
		out.WriteString(strings.ReplaceAll(h, "\r\n", m.Newline))
		out.WriteString(m.Newline)
	}
	out.WriteString(m.Newline)
	out.Write(m.Body)
	return out.Bytes()
}
