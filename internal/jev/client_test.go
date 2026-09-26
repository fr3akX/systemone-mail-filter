package jev

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fr3akX/systemone-mail-filter/internal/config"
	"github.com/fr3akX/systemone-mail-filter/internal/mailmsg"
)

func validResponse() map[string]any {
	a := map[string]any{}
	for _, name := range append([]string{"spam"}, Indicators...) {
		a[name] = map[string]any{"type": "noul", "noul": 0.98}
	}
	probabilities := map[string]float64{}
	for _, category := range Categories {
		probabilities[category] = 0.0
	}
	probabilities["correspondence"] = 1
	a["category"] = map[string]any{"type": "choice", "choice": "correspondence", "probabilities": probabilities}
	return map[string]any{"model": "jev-1.13.0", "answers": a}
}

func TestAPIRequestAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		bad    bool
	}{
		{"valid", func(map[string]any) {}, false},
		{"missing spam", func(r map[string]any) { delete(r["answers"].(map[string]any), "spam") }, true},
		{"null spam", func(r map[string]any) {
			r["answers"].(map[string]any)["spam"] = map[string]any{"type": "noul", "noul": nil}
		}, true},
		{"out of range", func(r map[string]any) {
			r["answers"].(map[string]any)["spam"] = map[string]any{"type": "noul", "noul": 1.1}
		}, true},
		{"missing indicator", func(r map[string]any) { delete(r["answers"].(map[string]any), "phishing") }, true},
		{"unknown category", func(r map[string]any) {
			r["answers"].(map[string]any)["category"].(map[string]any)["choice"] = "invented"
		}, true},
		{"null category probability", func(r map[string]any) {
			r["answers"].(map[string]any)["category"].(map[string]any)["probabilities"] = map[string]any{
				"correspondence": 1, "transactional_notification": 0, "newsletter": nil, "sales_outreach": 0, "other": 0,
			}
		}, true},
		{"header injection", func(r map[string]any) { r["model"] = "jev\r\nX-Injected: yes" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-key" || r.Method != http.MethodPost {
					t.Error("wrong authentication or method")
				}
				var req struct {
					Model     string              `json:"model"`
					State     mailmsg.State       `json:"state"`
					Questions map[string]question `json:"questions"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
				}
				if len(req.Questions) != 7 || req.State.Text != "synthetic mail" || req.Model != "jev-1.13.0" {
					t.Error("incorrect classification request")
				}
				if req.State.UntrustedHeader["x-spam-level"] != "*****" {
					t.Error("missing X-Spam-Level context")
				}
				response := validResponse()
				tc.mutate(response)
				json.NewEncoder(w).Encode(response)
			}))
			defer srv.Close()
			cfg := config.Default()
			cfg.APIURL = srv.URL
			result, err := New(cfg, "test-key").Classify(context.Background(), mailmsg.State{
				Text:            "synthetic mail",
				UntrustedHeader: map[string]string{"x-spam-level": "*****"},
			})
			if (err != nil) != tc.bad {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestCircuitAndErrorRedaction(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(429)
		w.Write([]byte("secret-key private email text"))
	}))
	defer srv.Close()
	cfg := config.Default()
	cfg.APIURL = srv.URL
	cfg.CircuitFailures = 2
	c := New(cfg, "secret-key")
	for i := 0; i < 3; i++ {
		_, err := c.Classify(context.Background(), mailmsg.State{})
		if err == nil || strings.Contains(err.Error(), "secret-key") || strings.Contains(err.Error(), "private email") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("circuit did not stop requests: %d", calls.Load())
	}
	c.mu.Lock()
	c.openUntil = time.Now().Add(-time.Second)
	c.mu.Unlock()
	c.Classify(context.Background(), mailmsg.State{})
	if calls.Load() != 3 {
		t.Fatal("circuit did not reopen for probe")
	}
}

func TestDeadlineAndNoRedirect(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
		}))
		defer srv.Close()
		cfg := config.Default()
		cfg.APIURL = srv.URL
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, err := New(cfg, "test").Classify(ctx, mailmsg.State{}); err == nil {
			t.Fatal("expected timeout")
		}
	})
	t.Run("redirect", func(t *testing.T) {
		var reached atomic.Bool
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
		defer target.Close()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
		defer srv.Close()
		cfg := config.Default()
		cfg.APIURL = srv.URL
		if _, err := New(cfg, "test").Classify(context.Background(), mailmsg.State{}); err == nil || reached.Load() {
			t.Fatal("redirect followed")
		}
	})
}
