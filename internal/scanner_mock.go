package internal

import "context"

// mockBackend returns configurable synthetic findings for testing.
type mockBackend struct {
	findings []FindingOutput
	passed   bool
}

func (b *mockBackend) ScanSAST(_ context.Context, opts SASTOpts) (*ScanOutput, error) {
	return b.buildResult(opts.Scanner), nil
}

func (b *mockBackend) ScanContainer(_ context.Context, opts ContainerOpts) (*ScanOutput, error) {
	return b.buildResult(opts.Scanner), nil
}

func (b *mockBackend) ScanDeps(_ context.Context, opts DepsOpts) (*ScanOutput, error) {
	return b.buildResult(opts.Scanner), nil
}

func (b *mockBackend) buildResult(scanner string) *ScanOutput {
	if scanner == "" {
		scanner = "mock"
	}
	out := &ScanOutput{
		Scanner:    scanner,
		PassedGate: b.passed,
		Findings:   b.findings,
	}
	if out.Findings == nil {
		out.Findings = []FindingOutput{}
	}
	// Compute summary from findings.
	for _, f := range out.Findings {
		switch f.Severity {
		case "critical":
			out.Summary.Critical++
		case "high":
			out.Summary.High++
		case "medium":
			out.Summary.Medium++
		case "low":
			out.Summary.Low++
		case "info":
			out.Summary.Info++
		}
	}
	return out
}
