package internal

import (
	"context"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type scanStep struct {
	name     string
	typeName string
	config   map[string]any
}

func newScanStep(typeName, name string, config map[string]any) (*scanStep, error) {
	switch typeName {
	case "step.sast_scan", "step.container_scan", "step.deps_scan":
		return &scanStep{name: name, typeName: typeName, config: config}, nil
	default:
		return nil, fmt.Errorf("security-scanner plugin: unknown step type %q", typeName)
	}
}

func (s *scanStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current map[string]any, _ map[string]any, config map[string]any) (*sdk.StepResult, error) {
	args := mergeConfigs(s.config, config, current)
	backend, err := backendFromArgs(args, "mock")
	if err != nil {
		return nil, err
	}
	module, err := newScannerModule(s.name, map[string]any{
		"sast_backend":      backend,
		"container_backend": backend,
		"deps_backend":      backend,
	})
	if err != nil {
		return nil, err
	}

	var out *ScanOutput
	switch s.typeName {
	case "step.sast_scan":
		out, err = module.sastBackend.ScanSAST(ctx, SASTOpts{
			Scanner:        stringArg(args, "scanner"),
			SourcePath:     stringArg(args, "source_path"),
			Rules:          stringSliceArg(args, "rules"),
			FailOnSeverity: stringArg(args, "fail_on_severity"),
			OutputFormat:   stringArg(args, "output_format"),
		})
	case "step.container_scan":
		out, err = module.containerBackend.ScanContainer(ctx, ContainerOpts{
			Scanner:           stringArg(args, "scanner"),
			TargetImage:       stringArg(args, "target_image"),
			SeverityThreshold: stringArg(args, "severity_threshold"),
			IgnoreUnfixed:     boolArg(args, "ignore_unfixed"),
			OutputFormat:      stringArg(args, "output_format"),
		})
	case "step.deps_scan":
		out, err = module.depsBackend.ScanDeps(ctx, DepsOpts{
			Scanner:        stringArg(args, "scanner"),
			SourcePath:     stringArg(args, "source_path"),
			FailOnSeverity: stringArg(args, "fail_on_severity"),
			OutputFormat:   stringArg(args, "output_format"),
		})
	}
	if err != nil {
		return nil, err
	}
	return &sdk.StepResult{Output: scanOutputToMap(out)}, nil
}

var _ sdk.StepInstance = (*scanStep)(nil)
