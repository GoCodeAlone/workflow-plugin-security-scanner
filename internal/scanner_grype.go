package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// grypeBackend runs grype CLI for dependency vulnerability scanning.
type grypeBackend struct{}

// grypeReport is the top-level structure of grype's JSON output.
type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln `json:"vulnerability"`
	Artifact      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"artifact"`
}

type grypeVuln struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Fix         struct {
		Versions []string `json:"versions"`
	} `json:"fix"`
}

func (b *grypeBackend) ScanSAST(_ context.Context, _ SASTOpts) (*ScanOutput, error) {
	return nil, fmt.Errorf("grype backend does not support SAST scanning; use semgrep")
}

func (b *grypeBackend) ScanContainer(_ context.Context, _ ContainerOpts) (*ScanOutput, error) {
	return nil, fmt.Errorf("grype backend does not support container scanning via this method; use trivy")
}

func (b *grypeBackend) ScanDeps(ctx context.Context, opts DepsOpts) (*ScanOutput, error) {
	args := []string{opts.SourcePath, "-o", "json", "--quiet"}

	out, err := exec.CommandContext(ctx, "grype", args...).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("grype: %w", err)
	}

	var report grypeReport
	if jsonErr := json.Unmarshal(out, &report); jsonErr != nil {
		return nil, fmt.Errorf("grype: parse output: %w", jsonErr)
	}

	scanner := opts.Scanner
	if scanner == "" {
		scanner = "grype"
	}

	output := &ScanOutput{
		Scanner:  scanner,
		Findings: make([]FindingOutput, 0, len(report.Matches)),
	}
	for _, m := range report.Matches {
		severity := strings.ToLower(m.Vulnerability.Severity)
		fixVersion := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixVersion = m.Vulnerability.Fix.Versions[0]
		}
		output.Findings = append(output.Findings, FindingOutput{
			RuleID:   m.Vulnerability.ID,
			Severity: severity,
			Message:  m.Vulnerability.Description,
			Location: fmt.Sprintf("%s@%s (fix: %s)", m.Artifact.Name, m.Artifact.Version, fixVersion),
		})
		computeSummary(&output.Summary, severity)
	}
	output.PassedGate = severityGatePasses(output.Findings, opts.FailOnSeverity)
	return output, nil
}
