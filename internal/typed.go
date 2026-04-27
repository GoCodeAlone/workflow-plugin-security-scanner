package internal

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-security-scanner/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func typedSASTScan() sdk.TypedStepHandler[*contracts.SASTScanConfig, *contracts.SASTScanInput, *contracts.ScanOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.SASTScanConfig, *contracts.SASTScanInput]) (*sdk.TypedStepResult[*contracts.ScanOutput], error) {
		args := mergeConfigs(sastConfigToMap(req.Config), sastInputToMap(req.Input), req.Current)
		backend, err := backendFromArgs(args, "mock")
		if err != nil {
			return nil, err
		}
		module, err := newScannerModule("typed-sast-step", map[string]any{"sast_backend": backend})
		if err != nil {
			return nil, err
		}
		out, err := module.sastBackend.ScanSAST(ctx, SASTOpts{
			Scanner:        stringArg(args, "scanner"),
			SourcePath:     stringArg(args, "source_path"),
			Rules:          stringSliceArg(args, "rules"),
			FailOnSeverity: stringArg(args, "fail_on_severity"),
			OutputFormat:   stringArg(args, "output_format"),
		})
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.ScanOutput]{Output: scanOutputToProto(out)}, nil
	}
}

func typedContainerScan() sdk.TypedStepHandler[*contracts.ContainerScanConfig, *contracts.ContainerScanInput, *contracts.ScanOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.ContainerScanConfig, *contracts.ContainerScanInput]) (*sdk.TypedStepResult[*contracts.ScanOutput], error) {
		args := mergeConfigs(containerConfigToMap(req.Config), containerInputToMap(req.Input), req.Current)
		backend, err := backendFromArgs(args, "mock")
		if err != nil {
			return nil, err
		}
		module, err := newScannerModule("typed-container-step", map[string]any{"container_backend": backend})
		if err != nil {
			return nil, err
		}
		out, err := module.containerBackend.ScanContainer(ctx, ContainerOpts{
			Scanner:           stringArg(args, "scanner"),
			TargetImage:       stringArg(args, "target_image"),
			SeverityThreshold: stringArg(args, "severity_threshold"),
			IgnoreUnfixed:     boolArg(args, "ignore_unfixed"),
			OutputFormat:      stringArg(args, "output_format"),
		})
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.ScanOutput]{Output: scanOutputToProto(out)}, nil
	}
}

func typedDepsScan() sdk.TypedStepHandler[*contracts.DepsScanConfig, *contracts.DepsScanInput, *contracts.ScanOutput] {
	return func(ctx context.Context, req sdk.TypedStepRequest[*contracts.DepsScanConfig, *contracts.DepsScanInput]) (*sdk.TypedStepResult[*contracts.ScanOutput], error) {
		args := mergeConfigs(depsConfigToMap(req.Config), depsInputToMap(req.Input), req.Current)
		backend, err := backendFromArgs(args, "mock")
		if err != nil {
			return nil, err
		}
		module, err := newScannerModule("typed-deps-step", map[string]any{"deps_backend": backend})
		if err != nil {
			return nil, err
		}
		out, err := module.depsBackend.ScanDeps(ctx, DepsOpts{
			Scanner:        stringArg(args, "scanner"),
			SourcePath:     stringArg(args, "source_path"),
			FailOnSeverity: stringArg(args, "fail_on_severity"),
			OutputFormat:   stringArg(args, "output_format"),
		})
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[*contracts.ScanOutput]{Output: scanOutputToProto(out)}, nil
	}
}

func (m *scannerModule) InvokeTypedMethod(method string, input *anypb.Any) (*anypb.Any, error) {
	switch method {
	case "ScanSAST":
		req, err := unpackTypedArgs(input, &contracts.ScanSASTRequest{})
		if err != nil {
			return nil, err
		}
		out, err := m.InvokeMethod(method, sastRequestToMap(req))
		if err != nil {
			return nil, err
		}
		return packScanMap(out)
	case "ScanContainer":
		req, err := unpackTypedArgs(input, &contracts.ScanContainerRequest{})
		if err != nil {
			return nil, err
		}
		out, err := m.InvokeMethod(method, containerRequestToMap(req))
		if err != nil {
			return nil, err
		}
		return packScanMap(out)
	case "ScanDeps":
		req, err := unpackTypedArgs(input, &contracts.ScanDepsRequest{})
		if err != nil {
			return nil, err
		}
		out, err := m.InvokeMethod(method, depsRequestToMap(req))
		if err != nil {
			return nil, err
		}
		return packScanMap(out)
	default:
		return nil, fmt.Errorf("security.scanner %q: unknown method %q", m.name, method)
	}
}

func unpackTypedArgs[T proto.Message](input *anypb.Any, target T) (T, error) {
	if input == nil {
		var zero T
		return zero, fmt.Errorf("typed input is required")
	}
	if input.MessageName() != target.ProtoReflect().Descriptor().FullName() {
		var zero T
		return zero, fmt.Errorf("typed input type mismatch: expected %s, got %s", target.ProtoReflect().Descriptor().FullName(), input.MessageName())
	}
	if err := input.UnmarshalTo(target); err != nil {
		var zero T
		return zero, err
	}
	return target, nil
}

func scannerModuleConfigToMap(cfg *contracts.ScannerModuleConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{
		"sast_backend":      cfg.GetSastBackend(),
		"container_backend": cfg.GetContainerBackend(),
		"deps_backend":      cfg.GetDepsBackend(),
		"mock_findings":     findingsToAny(cfg.GetMockFindings()),
		"mock_passed":       cfg.GetMockPassed(),
	})
}

func sastConfigToMap(cfg *contracts.SASTScanConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":          cfg.GetScanner(),
		"source_path":      cfg.GetSourcePath(),
		"rules":            stringsToAny(cfg.GetRules()),
		"fail_on_severity": cfg.GetFailOnSeverity(),
		"output_format":    cfg.GetOutputFormat(),
	})
}

func sastInputToMap(input *contracts.SASTScanInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":          input.GetScanner(),
		"source_path":      input.GetSourcePath(),
		"rules":            stringsToAny(input.GetRules()),
		"fail_on_severity": input.GetFailOnSeverity(),
		"output_format":    input.GetOutputFormat(),
	})
}

func sastRequestToMap(req *contracts.ScanSASTRequest) map[string]any {
	if req == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":          req.GetScanner(),
		"source_path":      req.GetSourcePath(),
		"rules":            stringsToAny(req.GetRules()),
		"fail_on_severity": req.GetFailOnSeverity(),
		"output_format":    req.GetOutputFormat(),
	})
}

func containerConfigToMap(cfg *contracts.ContainerScanConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":            cfg.GetScanner(),
		"target_image":       cfg.GetTargetImage(),
		"severity_threshold": cfg.GetSeverityThreshold(),
		"ignore_unfixed":     cfg.GetIgnoreUnfixed(),
		"output_format":      cfg.GetOutputFormat(),
	})
}

func containerInputToMap(input *contracts.ContainerScanInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":            input.GetScanner(),
		"target_image":       input.GetTargetImage(),
		"severity_threshold": input.GetSeverityThreshold(),
		"ignore_unfixed":     input.GetIgnoreUnfixed(),
		"output_format":      input.GetOutputFormat(),
	})
}

func containerRequestToMap(req *contracts.ScanContainerRequest) map[string]any {
	if req == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":            req.GetScanner(),
		"target_image":       req.GetTargetImage(),
		"severity_threshold": req.GetSeverityThreshold(),
		"ignore_unfixed":     req.GetIgnoreUnfixed(),
		"output_format":      req.GetOutputFormat(),
	})
}

func depsConfigToMap(cfg *contracts.DepsScanConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":          cfg.GetScanner(),
		"source_path":      cfg.GetSourcePath(),
		"fail_on_severity": cfg.GetFailOnSeverity(),
		"output_format":    cfg.GetOutputFormat(),
	})
}

func depsInputToMap(input *contracts.DepsScanInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":          input.GetScanner(),
		"source_path":      input.GetSourcePath(),
		"fail_on_severity": input.GetFailOnSeverity(),
		"output_format":    input.GetOutputFormat(),
	})
}

func depsRequestToMap(req *contracts.ScanDepsRequest) map[string]any {
	if req == nil {
		return nil
	}
	return compactMap(map[string]any{
		"scanner":          req.GetScanner(),
		"source_path":      req.GetSourcePath(),
		"fail_on_severity": req.GetFailOnSeverity(),
		"output_format":    req.GetOutputFormat(),
	})
}

func scanOutputToProto(out *ScanOutput) *contracts.ScanOutput {
	if out == nil {
		return nil
	}
	findings := make([]*contracts.Finding, 0, len(out.Findings))
	for _, finding := range out.Findings {
		findings = append(findings, &contracts.Finding{
			RuleId:   finding.RuleID,
			Severity: finding.Severity,
			Message:  finding.Message,
			Location: finding.Location,
			Line:     int32(finding.Line),
		})
	}
	return &contracts.ScanOutput{
		Scanner:    out.Scanner,
		PassedGate: out.PassedGate,
		Findings:   findings,
		Summary: &contracts.Summary{
			Critical: int32(out.Summary.Critical),
			High:     int32(out.Summary.High),
			Medium:   int32(out.Summary.Medium),
			Low:      int32(out.Summary.Low),
			Info:     int32(out.Summary.Info),
		},
	}
}

func scanOutputFromMap(values map[string]any) (*ScanOutput, error) {
	data, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	var out ScanOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if scanner := stringArg(values, "scanner"); scanner != "" {
		out.Scanner = scanner
	}
	if passed, ok := values["passed_gate"].(bool); ok {
		out.PassedGate = passed
	}
	return &out, nil
}

func packScanMap(values map[string]any) (*anypb.Any, error) {
	out, err := scanOutputFromMap(values)
	if err != nil {
		return nil, err
	}
	return anypb.New(scanOutputToProto(out))
}

func findingsToAny(findings []*contracts.Finding) []any {
	if len(findings) == 0 {
		return nil
	}
	out := make([]any, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		out = append(out, map[string]any{
			"rule_id":  finding.GetRuleId(),
			"severity": finding.GetSeverity(),
			"message":  finding.GetMessage(),
			"location": finding.GetLocation(),
			"line":     int(finding.GetLine()),
		})
	}
	return out
}

func stringsToAny(values []string) []any {
	if len(values) == 0 {
		return nil
	}
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func mergeConfigs(configs ...map[string]any) map[string]any {
	merged := map[string]any{}
	for _, config := range configs {
		for key, value := range config {
			merged[key] = value
		}
	}
	return merged
}

func compactMap(values map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range values {
		switch typed := value.(type) {
		case string:
			if typed != "" {
				out[key] = typed
			}
		case []any:
			if len(typed) > 0 {
				out[key] = typed
			}
		case bool:
			out[key] = typed
		default:
			if value != nil {
				out[key] = value
			}
		}
	}
	return out
}

func backendFromArgs(args map[string]any, fallback string) (string, error) {
	scanner := stringArg(args, "scanner")
	if scanner == "" {
		return fallback, nil
	}
	switch scanner {
	case "semgrep", "trivy", "grype", "mock":
		return scanner, nil
	default:
		return "", fmt.Errorf("unsupported scanner %q", scanner)
	}
}
