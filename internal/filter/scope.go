package filter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/fr3akX/systemone-mail-filter/internal/config"
	"github.com/fr3akX/systemone-mail-filter/internal/jev"
)

func recipientAllowed(cfg config.Config, address string) bool {
	if len(cfg.RecipientAddresses) == 0 && len(cfg.RecipientDomains) == 0 {
		return true
	}
	for _, allowed := range cfg.RecipientAddresses {
		if strings.EqualFold(address, allowed) {
			return true
		}
	}
	at := strings.LastIndexByte(address, '@')
	if at < 1 {
		return false
	}
	for _, domain := range cfg.RecipientDomains {
		if strings.EqualFold(address[at+1:], domain) {
			return true
		}
	}
	return false
}

// ProcessEnvelope applies recipient scope before parsing or contacting Jev.
// Match the actual delivery recipient. ORCPT is caller-supplied DSN metadata,
// not authorization to classify an otherwise out-of-scope recipient.
func (p *Processor) ProcessEnvelope(ctx context.Context, raw []byte, env Envelope) ([]byte, Report, error) {
	allowed := 0
	for _, recipient := range env.Recipients {
		if recipientAllowed(p.Config, recipient.Address) {
			allowed++
		}
	}
	if allowed == len(env.Recipients) && allowed > 0 {
		return p.Process(ctx, raw, env.From)
	}
	hash := sha256.Sum256(raw)
	report := Report{MessageHash: hex.EncodeToString(hash[:]), PolicyVersion: jev.PolicyVersion, Status: "bypassed"}
	if allowed > 0 || len(env.Recipients) == 0 {
		report.Status = "unclassified"
		report.Error = "recipient_scope_requires_separate_transactions"
		return nil, report, errors.New("recipient scope requires separate SMTP transactions; set systemone_destination_recipient_limit=1")
	}
	return raw, report, nil
}
