package internal

import (
	"context"
	"strings"
	"testing"
)

func TestMockBackend_ScanSAST_Passes(t *testing.T) {
	backend := &mockBackend{passed: true, findings: []FindingOutput{}}
	result, err := backend.ScanSAST(context.Background(), SASTOpts{Scanner: "mock"})
	if err != nil {
		t.Fatalf("ScanSAST error: %v", err)
	}
	if !result.PassedGate {
		t.Error("expected PassedGate=true")
	}
	if result.Scanner != "mock" {
		t.Errorf("expected scanner=mock, got %q", result.Scanner)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestMockBackend_ScanSAST_Fails(t *testing.T) {
	backend := &mockBackend{
		passed: false,
		findings: []FindingOutput{
			{RuleID: "sql-injection", Severity: "high", Message: "SQL injection risk"},
		},
	}
	result, err := backend.ScanSAST(context.Background(), SASTOpts{Scanner: "semgrep"})
	if err != nil {
		t.Fatalf("ScanSAST error: %v", err)
	}
	if result.PassedGate {
		t.Error("expected PassedGate=false")
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Summary.High != 1 {
		t.Errorf("expected Summary.High=1, got %d", result.Summary.High)
	}
}

func TestMockBackend_ScanContainer(t *testing.T) {
	backend := &mockBackend{
		passed: false,
		findings: []FindingOutput{
			{RuleID: "CVE-2024-1234", Severity: "critical", Message: "RCE vulnerability"},
		},
	}
	result, err := backend.ScanContainer(context.Background(), ContainerOpts{
		Scanner:           "trivy",
		TargetImage:       "myapp:latest",
		SeverityThreshold: "high",
	})
	if err != nil {
		t.Fatalf("ScanContainer error: %v", err)
	}
	if result.Scanner != "trivy" {
		t.Errorf("expected scanner=trivy, got %q", result.Scanner)
	}
	if result.Summary.Critical != 1 {
		t.Errorf("expected Summary.Critical=1, got %d", result.Summary.Critical)
	}
}

func TestMockBackend_ScanDeps(t *testing.T) {
	backend := &mockBackend{passed: true}
	result, err := backend.ScanDeps(context.Background(), DepsOpts{
		Scanner:        "grype",
		SourcePath:     "/workspace",
		FailOnSeverity: "high",
	})
	if err != nil {
		t.Fatalf("ScanDeps error: %v", err)
	}
	if !result.PassedGate {
		t.Error("expected PassedGate=true")
	}
}

func TestScannerModule_InvokeMethod_ScanSAST(t *testing.T) {
	m := &scannerModule{
		name:             "test",
		sastBackend:      &mockBackend{passed: true},
		containerBackend: &mockBackend{passed: true},
		depsBackend:      &mockBackend{passed: true},
	}

	result, err := m.InvokeMethod("ScanSAST", map[string]any{
		"scanner":     "mock",
		"source_path": "/src",
	})
	if err != nil {
		t.Fatalf("InvokeMethod error: %v", err)
	}
	if passed, _ := result["passed_gate"].(bool); !passed {
		t.Error("expected passed_gate=true")
	}
}

func TestScannerModule_InvokeMethod_ScanContainer(t *testing.T) {
	m := &scannerModule{
		name:             "test",
		sastBackend:      &mockBackend{},
		containerBackend: &mockBackend{passed: false, findings: []FindingOutput{{RuleID: "CVE-X", Severity: "high"}}},
		depsBackend:      &mockBackend{},
	}

	result, err := m.InvokeMethod("ScanContainer", map[string]any{
		"scanner":      "trivy",
		"target_image": "myapp:v1",
	})
	if err != nil {
		t.Fatalf("InvokeMethod error: %v", err)
	}
	if passed, _ := result["passed_gate"].(bool); passed {
		t.Error("expected passed_gate=false")
	}
}

func TestScannerModule_InvokeMethod_ScanDeps(t *testing.T) {
	m := &scannerModule{
		name:             "test",
		sastBackend:      &mockBackend{},
		containerBackend: &mockBackend{},
		depsBackend:      &mockBackend{passed: true},
	}

	result, err := m.InvokeMethod("ScanDeps", map[string]any{
		"scanner":          "grype",
		"source_path":      "/code",
		"fail_on_severity": "high",
	})
	if err != nil {
		t.Fatalf("InvokeMethod error: %v", err)
	}
	if passed, _ := result["passed_gate"].(bool); !passed {
		t.Error("expected passed_gate=true")
	}
}

func TestScanOutputToMapUsesProtoJSONKeys(t *testing.T) {
	result := scanOutputToMap(&ScanOutput{
		Scanner:    "mock",
		PassedGate: true,
		Findings: []FindingOutput{{
			RuleID:   "SEC001",
			Severity: "high",
			Message:  "example finding",
			Location: "main.go",
			Line:     12,
		}},
		Summary: SummaryOutput{High: 1},
	})

	for _, key := range []string{"Scanner", "PassedGate", "Findings", "Summary"} {
		if _, ok := result[key]; ok {
			t.Fatalf("scanOutputToMap emitted Go-style key %q", key)
		}
	}
	for _, key := range []string{"scanner", "passed_gate", "findings", "summary"} {
		if _, ok := result[key]; !ok {
			t.Fatalf("scanOutputToMap missing proto JSON key %q", key)
		}
	}
	summary, ok := result["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary = %T, want map[string]any", result["summary"])
	}
	if got, _ := summary["high"].(int); got != 1 {
		t.Fatalf("summary.high = %v, want 1", summary["high"])
	}
}

func TestScannerModule_InvokeMethod_UnknownMethod(t *testing.T) {
	m := &scannerModule{name: "test", sastBackend: &mockBackend{}}
	_, err := m.InvokeMethod("ScanUnknown", nil)
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
	if !strings.Contains(err.Error(), "unknown method") {
		t.Errorf("expected unknown method error, got: %v", err)
	}
}

func TestNewScannerModule_MockDefault(t *testing.T) {
	m, err := newScannerModule("test", map[string]any{})
	if err != nil {
		t.Fatalf("newScannerModule error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil module")
	}
}

func TestNewScannerModule_InvalidBackend(t *testing.T) {
	_, err := newScannerModule("test", map[string]any{
		"sast_backend": "invalid-tool",
	})
	if err == nil {
		t.Fatal("expected error for invalid backend")
	}
}

func TestSeverityRank(t *testing.T) {
	cases := []struct {
		severity string
		rank     int
	}{
		{"critical", 5},
		{"high", 4},
		{"medium", 3},
		{"low", 2},
		{"info", 1},
		{"unknown", 0},
	}
	for _, tc := range cases {
		got := severityRank(tc.severity)
		if got != tc.rank {
			t.Errorf("severityRank(%q)=%d, want %d", tc.severity, got, tc.rank)
		}
	}
}

func TestSeverityGatePasses(t *testing.T) {
	findings := []FindingOutput{
		{Severity: "medium"},
		{Severity: "low"},
	}
	if !severityGatePasses(findings, "high") {
		t.Error("gate should pass: no high+ findings")
	}
	if severityGatePasses(append(findings, FindingOutput{Severity: "high"}), "high") {
		t.Error("gate should fail: high finding present")
	}
}
