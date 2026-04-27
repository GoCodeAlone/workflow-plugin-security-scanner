package internal

import (
	"context"
	"encoding/json"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// scannerModule implements sdk.ModuleInstance and sdk.ServiceInvoker.
// It holds a configured backend for SAST, container, and dependency scanning.
type scannerModule struct {
	name             string
	sastBackend      Scanner
	containerBackend Scanner
	depsBackend      Scanner
}

// Scanner is the common interface for all scan backends.
type Scanner interface {
	ScanSAST(ctx context.Context, opts SASTOpts) (*ScanOutput, error)
	ScanContainer(ctx context.Context, opts ContainerOpts) (*ScanOutput, error)
	ScanDeps(ctx context.Context, opts DepsOpts) (*ScanOutput, error)
}

// SASTOpts are options for SAST scanning.
type SASTOpts struct {
	Scanner        string
	SourcePath     string
	Rules          []string
	FailOnSeverity string
	OutputFormat   string
}

// ContainerOpts are options for container scanning.
type ContainerOpts struct {
	Scanner           string
	TargetImage       string
	SeverityThreshold string
	IgnoreUnfixed     bool
	OutputFormat      string
}

// DepsOpts are options for dependency scanning.
type DepsOpts struct {
	Scanner        string
	SourcePath     string
	FailOnSeverity string
	OutputFormat   string
}

// ScanOutput is the result of a scan.
type ScanOutput struct {
	Scanner    string
	PassedGate bool
	Findings   []FindingOutput
	Summary    SummaryOutput
}

// FindingOutput is a single finding.
type FindingOutput struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
}

// SummaryOutput counts findings by severity.
type SummaryOutput struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// newScannerModule creates a scannerModule from the given config.
// Config keys:
//
//	sast_backend      - "semgrep" | "mock" (default: "mock")
//	container_backend - "trivy" | "mock" (default: "mock")
//	deps_backend      - "grype" | "trivy" | "mock" (default: "mock")
func newScannerModule(name string, config map[string]any) (*scannerModule, error) {
	sastBackendName, _ := config["sast_backend"].(string)
	if sastBackendName == "" {
		sastBackendName = "mock"
	}
	containerBackendName, _ := config["container_backend"].(string)
	if containerBackendName == "" {
		containerBackendName = "mock"
	}
	depsBackendName, _ := config["deps_backend"].(string)
	if depsBackendName == "" {
		depsBackendName = "mock"
	}

	// Extract mock_findings config for the mock backend.
	var mockFindings []FindingOutput
	if raw, ok := config["mock_findings"]; ok {
		b, err := json.Marshal(raw)
		if err == nil {
			_ = json.Unmarshal(b, &mockFindings) //nolint:errcheck // best-effort parse
		}
	}
	mockPassed, _ := config["mock_passed"].(bool)

	newBackend := func(backendName string) (Scanner, error) {
		switch backendName {
		case "semgrep":
			return &semgrepBackend{}, nil
		case "trivy":
			return &trivyBackend{}, nil
		case "grype":
			return &grypeBackend{}, nil
		case "mock":
			return &mockBackend{findings: mockFindings, passed: mockPassed}, nil
		default:
			return nil, fmt.Errorf("security.scanner %q: unknown backend %q", name, backendName)
		}
	}

	sast, err := newBackend(sastBackendName)
	if err != nil {
		return nil, err
	}
	container, err := newBackend(containerBackendName)
	if err != nil {
		return nil, err
	}
	deps, err := newBackend(depsBackendName)
	if err != nil {
		return nil, err
	}

	return &scannerModule{
		name:             name,
		sastBackend:      sast,
		containerBackend: container,
		depsBackend:      deps,
	}, nil
}

// Init is a no-op — service registration is handled by the host adapter.
func (m *scannerModule) Init() error { return nil }

// Start is a no-op.
func (m *scannerModule) Start(_ context.Context) error { return nil }

// Stop is a no-op.
func (m *scannerModule) Stop(_ context.Context) error { return nil }

// InvokeMethod dispatches scan method calls from the host.
// Supported methods: ScanSAST, ScanContainer, ScanDeps.
func (m *scannerModule) InvokeMethod(method string, args map[string]any) (map[string]any, error) {
	ctx := context.Background()

	switch method {
	case "ScanSAST":
		opts := SASTOpts{
			Scanner:        stringArg(args, "scanner"),
			SourcePath:     stringArg(args, "source_path"),
			Rules:          stringSliceArg(args, "rules"),
			FailOnSeverity: stringArg(args, "fail_on_severity"),
			OutputFormat:   stringArg(args, "output_format"),
		}
		result, err := m.sastBackend.ScanSAST(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("ScanSAST: %w", err)
		}
		return scanOutputToMap(result), nil

	case "ScanContainer":
		opts := ContainerOpts{
			Scanner:           stringArg(args, "scanner"),
			TargetImage:       stringArg(args, "target_image"),
			SeverityThreshold: stringArg(args, "severity_threshold"),
			IgnoreUnfixed:     boolArg(args, "ignore_unfixed"),
			OutputFormat:      stringArg(args, "output_format"),
		}
		result, err := m.containerBackend.ScanContainer(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("ScanContainer: %w", err)
		}
		return scanOutputToMap(result), nil

	case "ScanDeps":
		opts := DepsOpts{
			Scanner:        stringArg(args, "scanner"),
			SourcePath:     stringArg(args, "source_path"),
			FailOnSeverity: stringArg(args, "fail_on_severity"),
			OutputFormat:   stringArg(args, "output_format"),
		}
		result, err := m.depsBackend.ScanDeps(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("ScanDeps: %w", err)
		}
		return scanOutputToMap(result), nil

	default:
		return nil, fmt.Errorf("security.scanner %q: unknown method %q", m.name, method)
	}
}

// Ensure scannerModule satisfies sdk.ServiceInvoker.
var _ sdk.ServiceInvoker = (*scannerModule)(nil)

// scanOutputToMap converts a ScanOutput to a map[string]any for gRPC transport.
func scanOutputToMap(out *ScanOutput) map[string]any {
	findings := make([]any, 0, len(out.Findings))
	for _, finding := range out.Findings {
		item := map[string]any{
			"rule_id":  finding.RuleID,
			"severity": finding.Severity,
			"message":  finding.Message,
			"location": finding.Location,
		}
		if finding.Line != 0 {
			item["line"] = finding.Line
		}
		findings = append(findings, item)
	}

	return map[string]any{
		"scanner":     out.Scanner,
		"passed_gate": out.PassedGate,
		"findings":    findings,
		"summary": map[string]any{
			"critical": out.Summary.Critical,
			"high":     out.Summary.High,
			"medium":   out.Summary.Medium,
			"low":      out.Summary.Low,
			"info":     out.Summary.Info,
		},
	}
}

// --- Argument helpers ---

func stringArg(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}

func boolArg(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

func stringSliceArg(args map[string]any, key string) []string {
	raw, ok := args[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
