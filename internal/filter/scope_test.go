package filter

import (
	"bytes"
	"context"
	"testing"

	"github.com/emersion/go-smtp"
	"github.com/fr3akX/systemone-mail-filter/internal/config"
	"github.com/fr3akX/systemone-mail-filter/internal/jev"
	"github.com/fr3akX/systemone-mail-filter/internal/mailmsg"
)

func TestRecipientScope(t *testing.T) {
	cfg := config.Default()
	cfg.RecipientAddresses = []string{"alice@example.org"}
	cfg.RecipientDomains = []string{"marketing.example", "company.example"}
	for address, want := range map[string]bool{
		"alice@example.org":               true,
		"ALICE@EXAMPLE.ORG":               true,
		"other@example.org":               false,
		"someone@marketing.example":       true,
		"someone@company.example":         true,
		"someone@sub.company.example":     false,
		"someone@notcompany.example":      false,
		"someone@company.example.example": false,
		"someone@example.net":             false,
	} {
		if got := recipientAllowed(cfg, address); got != want {
			t.Errorf("%s: got %t, want %t", address, got, want)
		}
	}
	for _, tc := range []struct {
		name       string
		recipients []Recipient
		wantCalls  int
		wantStatus string
		wantError  bool
	}{
		{"allowed", []Recipient{{Address: "alice@company.example"}}, 1, "spam", false},
		{"outside", []Recipient{{Address: "someone@example.net"}}, 0, "bypassed", false},
		{"forged ORCPT", []Recipient{{Address: "someone@example.net", Options: smtp.RcptOptions{OriginalRecipient: "alice@company.example"}}}, 0, "bypassed", false},
		{"mixed", []Recipient{{Address: "alice@company.example"}, {Address: "someone@example.net"}}, 0, "unclassified", true},
		{"empty", nil, 0, "unclassified", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			p := Processor{Config: cfg, Classifier: classifierFunc(func(ctx context.Context, s mailmsg.State) (jev.Result, error) {
				calls++
				return classifier(0.99, nil).Classify(ctx, s)
			})}
			raw := []byte(message)
			out, report, err := p.ProcessEnvelope(context.Background(), raw, Envelope{Recipients: tc.recipients})
			if calls != tc.wantCalls || report.Status != tc.wantStatus || (err != nil) != tc.wantError {
				t.Fatalf("calls=%d report=%#v err=%v", calls, report, err)
			}
			if tc.wantStatus == "bypassed" && !bytes.Equal(raw, out) {
				t.Fatal("bypassed message changed")
			}
		})
	}
}
