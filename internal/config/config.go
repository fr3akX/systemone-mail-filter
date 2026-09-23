package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Listen                 string   `json:"listen"`
	Reinject               string   `json:"reinject"`
	Hostname               string   `json:"hostname"`
	SubjectPrefix          string   `json:"subject_prefix"`
	SpamThreshold          float64  `json:"spam_threshold"`
	OnError                string   `json:"on_error"`
	APIURL                 string   `json:"api_url"`
	Model                  string   `json:"model"`
	APITimeoutSeconds      int      `json:"api_timeout_seconds"`
	SMTPTimeoutSeconds     int      `json:"smtp_timeout_seconds"`
	MaxMessageBytes        int64    `json:"max_message_bytes"`
	MaxStateBytes          int      `json:"max_state_bytes"`
	MaxConnections         int      `json:"max_connections"`
	MaxRecipients          int      `json:"max_recipients"`
	CircuitFailures        int      `json:"circuit_failures"`
	CircuitCooldownSeconds int      `json:"circuit_cooldown_seconds"`
	RecipientAddresses     []string `json:"recipient_addresses,omitempty"`
	RecipientDomains       []string `json:"recipient_domains,omitempty"`
}

func Default() Config {
	return Config{
		Listen: "127.0.0.1:10025", Reinject: "127.0.0.1:10026", Hostname: "systemone-mail-filter.local",
		SubjectPrefix: "[SPAM]", SpamThreshold: 0.95, OnError: "deliver_unmodified",
		APIURL: "https://api.typesafe.ai/v1/systemone", Model: "jev-1.13.0",
		APITimeoutSeconds: 5, SMTPTimeoutSeconds: 60, MaxMessageBytes: 25 * 1024 * 1024,
		MaxStateBytes: 24000, MaxConnections: 8, MaxRecipients: 1000,
		CircuitFailures: 5, CircuitCooldownSeconds: 30,
	}
}

func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, err
		}
		defer f.Close()
		d := json.NewDecoder(f)
		d.DisallowUnknownFields()
		if err := d.Decode(&c); err != nil {
			return c, fmt.Errorf("config: %w", err)
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return c, fmt.Errorf("config must contain one JSON object")
		}
	}
	return c, c.Validate()
}

func LoopbackAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q", addr)
	}
	ip := net.ParseIP(host)
	n, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("address %q must use a literal loopback IP and a port from 1 to 65535", addr)
	}
	return nil
}

func (c Config) Validate() error {
	for _, address := range c.RecipientAddresses {
		parsed, err := mail.ParseAddress(address)
		if err != nil || parsed.Name != "" || parsed.Address != address || strings.Count(address, "@") != 1 {
			return fmt.Errorf("recipient_addresses must contain plain mailbox addresses")
		}
	}
	for _, domain := range c.RecipientDomains {
		if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, "@* \t\r\n") {
			return fmt.Errorf("recipient_domains must contain exact DNS domain names")
		}
		for _, label := range strings.Split(domain, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.IndexFunc(label, func(r rune) bool {
				return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
			}) >= 0 {
				return fmt.Errorf("recipient_domains must contain exact DNS domain names")
			}
		}
	}
	if err := LoopbackAddress(c.Listen); err != nil {
		return err
	}
	if err := LoopbackAddress(c.Reinject); err != nil {
		return err
	}
	lh, lp, _ := net.SplitHostPort(c.Listen)
	rh, rp, _ := net.SplitHostPort(c.Reinject)
	listenPort, _ := strconv.Atoi(lp)
	relayPort, _ := strconv.Atoi(rp)
	if net.ParseIP(lh).Equal(net.ParseIP(rh)) && listenPort == relayPort {
		return fmt.Errorf("listen and reinject must differ")
	}
	for name, value := range map[string]string{"hostname": c.Hostname, "model": c.Model} {
		if value == "" || len(value) > 200 || strings.IndexFunc(value, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 {
			return fmt.Errorf("%s must be a nonempty ASCII token", name)
		}
	}
	if strings.TrimSpace(c.SubjectPrefix) == "" || len(c.SubjectPrefix) > 100 || strings.IndexFunc(c.SubjectPrefix, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return fmt.Errorf("subject_prefix must contain 1-100 bytes without control characters")
	}
	if !(c.SpamThreshold >= 0 && c.SpamThreshold <= 1) {
		return fmt.Errorf("spam_threshold must be between 0 and 1")
	}
	if c.OnError != "deliver_unmodified" && c.OnError != "defer" {
		return fmt.Errorf("on_error must be deliver_unmodified or defer")
	}
	u, err := url.Parse(c.APIURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid api_url")
	}
	local := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && local != nil && local.IsLoopback()) {
		return fmt.Errorf("api_url requires HTTPS (HTTP allowed only on literal loopback IPs)")
	}
	if c.APITimeoutSeconds < 1 || c.APITimeoutSeconds > 120 || c.SMTPTimeoutSeconds <= c.APITimeoutSeconds || c.SMTPTimeoutSeconds > 600 {
		return fmt.Errorf("timeouts require 1 <= api <= 120 and api < smtp <= 600 seconds")
	}
	if c.MaxMessageBytes < 1024 || c.MaxMessageBytes > 100*1024*1024 || c.MaxStateBytes < 4096 || c.MaxStateBytes > 24000 {
		return fmt.Errorf("max_message_bytes must be 1KiB-100MiB; max_state_bytes must be 4096-24000")
	}
	if c.MaxConnections < 1 || c.MaxConnections > 128 || c.MaxRecipients < 1 || c.MaxRecipients > 10000 || c.CircuitFailures < 1 || c.CircuitCooldownSeconds < 1 || c.CircuitCooldownSeconds > 3600 {
		return fmt.Errorf("invalid concurrency, recipient, or circuit limits")
	}
	return nil
}
