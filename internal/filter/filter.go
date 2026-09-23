package filter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/fr3akX/systemone-mail-filter/internal/config"
	"github.com/fr3akX/systemone-mail-filter/internal/jev"
	"github.com/fr3akX/systemone-mail-filter/internal/mailmsg"
)

type Report struct {
	MessageHash   string      `json:"message_hash"`
	Status        string      `json:"status"`
	Tagged        bool        `json:"tagged"`
	Truncated     bool        `json:"truncated"`
	PolicyVersion string      `json:"policy_version"`
	Result        *jev.Result `json:"classification,omitempty"`
	Error         string      `json:"error,omitempty"`
}

type Processor struct {
	Config     config.Config
	Classifier jev.Classifier
}

func (p *Processor) Process(ctx context.Context, raw []byte, from string) ([]byte, Report, error) {
	hash := sha256.Sum256(raw)
	report := Report{MessageHash: hex.EncodeToString(hash[:]), Status: "unclassified", PolicyVersion: jev.PolicyVersion}
	m, err := mailmsg.Parse(raw)
	if err != nil {
		// Without valid headers we cannot safely remove forged diagnostic fields.
		report.Error = "invalid_message_headers"
		return nil, report, fmt.Errorf("cannot safely rewrite message headers")
	}
	state, err := m.Extract(from, p.Config.MaxStateBytes)
	report.Truncated = state.Truncated
	var result jev.Result
	if err == nil {
		result, err = p.Classifier.Classify(ctx, state)
	}
	if err != nil {
		report.Error = err.Error()
		if p.Config.OnError == "defer" {
			return nil, report, err
		}
		return m.Rewrite("", false, []string{
			"X-SystemOne-Filter: verdict=unclassified; policy=" + jev.PolicyVersion,
			"X-SystemOne-Spam: Unknown",
		}), report, nil
	}
	report.Result = &result
	report.Status = "ham"
	report.Tagged = result.SpamProbability >= p.Config.SpamThreshold
	spam := "No"
	if report.Tagged {
		report.Status = "spam"
		spam = "Yes"
	}
	headers := []string{
		fmt.Sprintf("X-SystemOne-Filter: verdict=%s; model=%s; policy=%s; truncated=%t", report.Status, result.Model, jev.PolicyVersion, report.Truncated),
		fmt.Sprintf("X-SystemOne-Spam: %s; probability=%.6f", spam, result.SpamProbability),
		"X-SystemOne-Category: " + result.Category,
	}
	var probabilities []string
	for _, category := range jev.Categories {
		probabilities = append(probabilities, fmt.Sprintf("%s=%.6f", category, result.CategoryProbabilities[category]))
	}
	headers = append(headers, "X-SystemOne-Category-Probabilities: "+strings.Join(probabilities, ";\r\n "))
	probabilities = nil
	for _, indicator := range jev.Indicators {
		probabilities = append(probabilities, fmt.Sprintf("%s=%.6f", indicator, result.Abuse[indicator]))
	}
	headers = append(headers, "X-SystemOne-Abuse: "+strings.Join(probabilities, ";\r\n "))
	return m.Rewrite(p.Config.SubjectPrefix, report.Tagged, headers), report, nil
}
