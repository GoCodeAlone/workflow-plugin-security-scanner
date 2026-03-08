package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// semgrepBackend runs semgrep CLI for SAST scanning.
type semgrepBackend struct{}

// semgrepResult is the top-level structure of semgrep's JSON output.
type semgrepResult struct {
	Results []semgrepFinding `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type semgrepFinding struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
	} `json:"extra"`
}

func (b *semgrepBackend) ScanSAST(ctx context.Context, opts SASTOpts) (*ScanOutput, error) {
	args := []string{"scan", "--json"}
	for _, rule := range opts.Rules {
		args = append(args, "--config", rule)
	}
	args = append(args, opts.SourcePath)

	out, err := exec.CommandContext(ctx, "semgrep", args...).Output()
	if err != nil {
		// semgrep exits non-zero when findings exist; attempt to parse JSON anyway.
		if len(out) == 0 {
			return nil, fmt.Errorf("semgrep: %w", err)
		}
	}

	var result semgrepResult
	if jsonErr := json.Unmarshal(out, &result); jsonErr != nil {
		return nil, fmt.Errorf("semgrep: parse output: %w", jsonErr)
	}

	output := &ScanOutput{
		Scanner:  "semgrep",
		Findings: make([]FindingOutput, 0, len(result.Results)),
	}
	for _, f := range result.Results {
		severity := strings.ToLower(f.Extra.Severity)
		if severity == "error" {
			severity = "high"
		} else if severity == "warning" {
			severity = "medium"
		} else if severity == "info" {
			severity = "info"
		}
		output.Findings = append(output.Findings, FindingOutput{
			RuleID:   f.CheckID,
			Severity: severity,
			Message:  f.Extra.Message,
			Location: f.Path,
			Line:     f.Start.Line,
		})
		computeSummary(&output.Summary, severity)
	}
	output.PassedGate = severityGatePasses(output.Findings, opts.FailOnSeverity)
	return output, nil
}

func (b *semgrepBackend) ScanContainer(_ context.Context, _ ContainerOpts) (*ScanOutput, error) {
	return nil, fmt.Errorf("semgrep backend does not support container scanning; use trivy")
}

func (b *semgrepBackend) ScanDeps(_ context.Context, _ DepsOpts) (*ScanOutput, error) {
	return nil, fmt.Errorf("semgrep backend does not support dependency scanning; use grype or trivy")
}

// computeSummary increments the appropriate severity counter.
func computeSummary(s *SummaryOutput, severity string) {
	switch severity {
	case "critical":
		s.Critical++
	case "high":
		s.High++
	case "medium":
		s.Medium++
	case "low":
		s.Low++
	case "info":
		s.Info++
	}
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// severityGatePasses returns true if no finding is at or above the threshold.
func severityGatePasses(findings []FindingOutput, threshold string) bool {
	rank := severityRank(threshold)
	if rank == 0 {
		return true
	}
	for _, f := range findings {
		if severityRank(f.Severity) >= rank {
			return false
		}
	}
	return true
}
