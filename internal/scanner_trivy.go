package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// trivyBackend runs trivy CLI for container and dependency scanning.
type trivyBackend struct{}

// trivyReport is the top-level structure of trivy's JSON output.
type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string           `json:"Target"`
	Vulnerabilities []trivyVulnEntry `json:"Vulnerabilities"`
}

type trivyVulnEntry struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Title            string `json:"Title"`
	Severity         string `json:"Severity"`
}

func (b *trivyBackend) ScanSAST(_ context.Context, _ SASTOpts) (*ScanOutput, error) {
	return nil, fmt.Errorf("trivy backend does not support SAST scanning; use semgrep")
}

func (b *trivyBackend) ScanContainer(ctx context.Context, opts ContainerOpts) (*ScanOutput, error) {
	args := []string{"image", "--format", "json", "--quiet"}
	if opts.SeverityThreshold != "" {
		args = append(args, "--severity", strings.ToUpper(opts.SeverityThreshold)+",CRITICAL")
	}
	if opts.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}
	args = append(args, opts.TargetImage)

	out, err := exec.CommandContext(ctx, "trivy", args...).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("trivy: %w", err)
	}

	return b.parseReport(out, opts.Scanner, opts.SeverityThreshold)
}

func (b *trivyBackend) ScanDeps(ctx context.Context, opts DepsOpts) (*ScanOutput, error) {
	args := []string{"fs", "--format", "json", "--quiet"}
	if opts.FailOnSeverity != "" {
		args = append(args, "--severity", strings.ToUpper(opts.FailOnSeverity)+",CRITICAL")
	}
	args = append(args, opts.SourcePath)

	out, err := exec.CommandContext(ctx, "trivy", args...).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("trivy: %w", err)
	}

	return b.parseReport(out, opts.Scanner, opts.FailOnSeverity)
}

func (b *trivyBackend) parseReport(data []byte, scannerName, threshold string) (*ScanOutput, error) {
	if scannerName == "" {
		scannerName = "trivy"
	}
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("trivy: parse output: %w", err)
	}

	output := &ScanOutput{
		Scanner:  scannerName,
		Findings: []FindingOutput{},
	}
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			severity := strings.ToLower(v.Severity)
			output.Findings = append(output.Findings, FindingOutput{
				RuleID:   v.VulnerabilityID,
				Severity: severity,
				Message:  v.Title,
				Location: fmt.Sprintf("%s@%s", v.PkgName, v.InstalledVersion),
			})
			computeSummary(&output.Summary, severity)
		}
	}
	output.PassedGate = severityGatePasses(output.Findings, threshold)
	return output, nil
}
