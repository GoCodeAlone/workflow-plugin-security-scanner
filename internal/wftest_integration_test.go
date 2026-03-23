package internal_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow/wftest"
)

// TestWFTest_SASTScanPipeline_Passes verifies a SAST scan pipeline where
// the scan step reports no vulnerabilities and the gate passes.
func TestWFTest_SASTScanPipeline_Passes(t *testing.T) {
	scanRec := wftest.RecordStep("step.sast_scan")
	scanRec.WithOutput(map[string]any{
		"passed_gate":      true,
		"scanner":         "semgrep",
		"finding_count":   0,
		"vulnerabilities": []any{},
	})

	h := wftest.New(t, wftest.WithYAML(`
pipelines:
  run-sast-scan:
    trigger:
      type: manual
    steps:
      - name: sast_scan
        type: step.sast_scan
        config:
          scanner: semgrep
          source_path: ./src
          fail_on_severity: high
`), scanRec)

	result := h.ExecutePipeline("run-sast-scan", map[string]any{
		"repo":   "myapp",
		"branch": "main",
	})
	if result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}
	if scanRec.CallCount() != 1 {
		t.Errorf("expected 1 call to sast_scan step, got %d", scanRec.CallCount())
	}
	stepOut := result.StepOutput("sast_scan")
	if stepOut["passed_gate"] != true {
		t.Errorf("expected passed_gate=true, got %v", stepOut["passed_gate"])
	}
	if stepOut["finding_count"] != 0 {
		t.Errorf("expected finding_count=0, got %v", stepOut["finding_count"])
	}
}

// TestWFTest_ContainerScanPipeline_FindingsDetected verifies a container scan
// pipeline where critical vulnerabilities are found and the gate fails.
func TestWFTest_ContainerScanPipeline_FindingsDetected(t *testing.T) {
	containerScanRec := wftest.RecordStep("step.container_scan")
	containerScanRec.WithOutput(map[string]any{
		"passed_gate": false,
		"scanner":     "trivy",
		"findings": []any{
			map[string]any{
				"rule_id":  "CVE-2024-1234",
				"severity": "critical",
				"message":  "Remote code execution vulnerability",
			},
		},
		"summary": map[string]any{
			"critical": 1,
			"high":     0,
		},
	})

	h := wftest.New(t, wftest.WithYAML(`
pipelines:
  scan-container-image:
    trigger:
      type: manual
    steps:
      - name: container_scan
        type: step.container_scan
        config:
          scanner: trivy
          target_image: myapp:latest
          severity_threshold: high
`), containerScanRec)

	result := h.ExecutePipeline("scan-container-image", map[string]any{
		"image": "myapp:latest",
	})
	if result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}
	if containerScanRec.CallCount() != 1 {
		t.Errorf("expected 1 call to container_scan step, got %d", containerScanRec.CallCount())
	}
	stepOut := result.StepOutput("container_scan")
	if stepOut["passed_gate"] != false {
		t.Errorf("expected passed_gate=false due to critical CVE, got %v", stepOut["passed_gate"])
	}
	calls := containerScanRec.Calls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].Config["scanner"] != "trivy" {
		t.Errorf("expected scanner=trivy in step config, got %v", calls[0].Config["scanner"])
	}
}

// TestWFTest_DepsScanPipeline_MultiStep verifies a pipeline that runs both
// SAST and dependency scans sequentially, checking each step's recorded output.
func TestWFTest_DepsScanPipeline_MultiStep(t *testing.T) {
	sastRec := wftest.RecordStep("step.sast_scan")
	sastRec.WithOutput(map[string]any{
		"passed_gate": true,
		"scanner":     "semgrep",
	})

	depsRec := wftest.RecordStep("step.deps_scan")
	depsRec.WithOutput(map[string]any{
		"passed_gate": true,
		"scanner":     "grype",
		"finding_count": 0,
	})

	h := wftest.New(t, wftest.WithYAML(`
pipelines:
  full-security-scan:
    trigger:
      type: manual
    steps:
      - name: sast_scan
        type: step.sast_scan
        config:
          scanner: semgrep
          source_path: ./src
      - name: deps_scan
        type: step.deps_scan
        config:
          scanner: grype
          source_path: ./
          fail_on_severity: high
`), sastRec, depsRec)

	result := h.ExecutePipeline("full-security-scan", map[string]any{
		"repo": "myapp",
	})
	if result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}
	if sastRec.CallCount() != 1 {
		t.Errorf("expected 1 call to sast_scan, got %d", sastRec.CallCount())
	}
	if depsRec.CallCount() != 1 {
		t.Errorf("expected 1 call to deps_scan, got %d", depsRec.CallCount())
	}

	sastOut := result.StepOutput("sast_scan")
	if sastOut["passed_gate"] != true {
		t.Errorf("sast_scan: expected passed_gate=true, got %v", sastOut["passed_gate"])
	}

	depsOut := result.StepOutput("deps_scan")
	if depsOut["passed_gate"] != true {
		t.Errorf("deps_scan: expected passed_gate=true, got %v", depsOut["passed_gate"])
	}
	if depsOut["finding_count"] != 0 {
		t.Errorf("deps_scan: expected finding_count=0, got %v", depsOut["finding_count"])
	}
}
