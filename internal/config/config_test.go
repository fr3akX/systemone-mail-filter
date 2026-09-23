package config

import "testing"

func TestValidation(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"public listener":  func(c *Config) { c.Listen = "0.0.0.0:10025" },
		"remote relay":     func(c *Config) { c.Reinject = "192.0.2.1:25" },
		"relay loop":       func(c *Config) { c.Reinject = c.Listen },
		"prefix injection": func(c *Config) { c.SubjectPrefix = "spam\r\nX-Evil: yes" },
		"threshold":        func(c *Config) { c.SpamThreshold = 1.1 },
		"error policy":     func(c *Config) { c.OnError = "discard" },
		"insecure API":     func(c *Config) { c.APIURL = "http://api.example.org" },
		"bad timeout":      func(c *Config) { c.SMTPTimeoutSeconds = c.APITimeoutSeconds },
		"bad state size":   func(c *Config) { c.MaxStateBytes = 100000 },
		"zero concurrency": func(c *Config) { c.MaxConnections = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}
