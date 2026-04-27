package internal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-security-scanner/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestPluginImplementsStrictContractProviders(t *testing.T) {
	provider := NewSecurityScannerPlugin()
	if _, ok := provider.(sdk.TypedModuleProvider); !ok {
		t.Fatal("expected TypedModuleProvider")
	}
	if _, ok := provider.(sdk.TypedStepProvider); !ok {
		t.Fatal("expected TypedStepProvider")
	}
	if _, ok := provider.(sdk.ContractProvider); !ok {
		t.Fatal("expected ContractProvider")
	}
}

func TestContractRegistryDeclaresStrictModuleStepAndServiceContracts(t *testing.T) {
	provider := NewSecurityScannerPlugin().(sdk.ContractProvider)
	registry := provider.ContractRegistry()
	if registry == nil {
		t.Fatal("expected contract registry")
	}
	if registry.FileDescriptorSet == nil || len(registry.FileDescriptorSet.File) == 0 {
		t.Fatal("expected file descriptor set")
	}
	files, err := protodesc.NewFiles(registry.FileDescriptorSet)
	if err != nil {
		t.Fatalf("descriptor set: %v", err)
	}

	manifestContracts := loadManifestContracts(t)
	contractsByKey := make(map[string]*pb.ContractDescriptor, len(registry.Contracts))
	for _, contract := range registry.Contracts {
		if contract.Mode != pb.ContractMode_CONTRACT_MODE_STRICT_PROTO {
			t.Fatalf("%s mode = %s, want strict proto", contractKey(contract), contract.Mode)
		}
		for _, name := range []string{contract.ConfigMessage, contract.InputMessage, contract.OutputMessage} {
			if name == "" {
				continue
			}
			if _, err := files.FindDescriptorByName(protoreflect.FullName(name)); err != nil {
				t.Fatalf("%s references unknown message %s: %v", contractKey(contract), name, err)
			}
		}
		key := contractKey(contract)
		if _, exists := contractsByKey[key]; exists {
			t.Fatalf("duplicate runtime contract %q", key)
		}
		contractsByKey[key] = contract
		want, ok := manifestContracts[key]
		if !ok {
			t.Fatalf("%s missing from plugin.contracts.json", key)
		}
		if want.ConfigMessage != contract.ConfigMessage || want.InputMessage != contract.InputMessage || want.OutputMessage != contract.OutputMessage {
			t.Fatalf("%s manifest contract = %#v, runtime = %#v", key, want, contract)
		}
	}
	if len(contractsByKey) != len(manifestContracts) {
		t.Fatalf("runtime contract count = %d, manifest = %d", len(contractsByKey), len(manifestContracts))
	}

	wantKeys := []string{
		"module:security.scanner",
		"step:step.sast_scan",
		"step:step.container_scan",
		"step:step.deps_scan",
		"service:security.scanner/ScanSAST",
		"service:security.scanner/ScanContainer",
		"service:security.scanner/ScanDeps",
	}
	for _, key := range wantKeys {
		if _, ok := contractsByKey[key]; !ok {
			t.Fatalf("missing runtime contract %q", key)
		}
	}
}

func TestTypeListsAreDefensiveCopies(t *testing.T) {
	provider := NewSecurityScannerPlugin()
	moduleProvider := provider.(sdk.ModuleProvider)
	typedModuleProvider := provider.(sdk.TypedModuleProvider)
	stepProvider := provider.(sdk.StepProvider)
	typedStepProvider := provider.(sdk.TypedStepProvider)

	moduleTypes := moduleProvider.ModuleTypes()
	moduleTypes[0] = "mutated"
	if got := moduleProvider.ModuleTypes()[0]; got == "mutated" {
		t.Fatal("ModuleTypes exposed mutable package-level slice")
	}

	typedModuleTypes := typedModuleProvider.TypedModuleTypes()
	typedModuleTypes[0] = "mutated"
	if got := typedModuleProvider.TypedModuleTypes()[0]; got == "mutated" {
		t.Fatal("TypedModuleTypes exposed mutable package-level slice")
	}

	stepTypes := stepProvider.StepTypes()
	stepTypes[0] = "mutated"
	if got := stepProvider.StepTypes()[0]; got == "mutated" {
		t.Fatal("StepTypes exposed mutable package-level slice")
	}

	typedStepTypes := typedStepProvider.TypedStepTypes()
	typedStepTypes[0] = "mutated"
	if got := typedStepProvider.TypedStepTypes()[0]; got == "mutated" {
		t.Fatal("TypedStepTypes exposed mutable package-level slice")
	}
}

func TestTypedScannerModuleValidatesConfigAndServiceInput(t *testing.T) {
	provider := NewSecurityScannerPlugin().(sdk.TypedModuleProvider)
	config, err := anypb.New(&contracts.ScannerModuleConfig{SastBackend: "mock", MockPassed: true})
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	module, err := provider.CreateTypedModule("security.scanner", "scanner", config)
	if err != nil {
		t.Fatalf("CreateTypedModule: %v", err)
	}
	invoker, ok := module.(sdk.TypedServiceInvoker)
	if !ok {
		t.Fatal("expected TypedServiceInvoker")
	}
	input, err := anypb.New(&contracts.ScanSASTRequest{Scanner: "mock", SourcePath: "./src"})
	if err != nil {
		t.Fatalf("pack input: %v", err)
	}
	output, err := invoker.InvokeTypedMethod("ScanSAST", input)
	if err != nil {
		t.Fatalf("InvokeTypedMethod(ScanSAST): %v", err)
	}
	var scan contracts.ScanOutput
	if err := output.UnmarshalTo(&scan); err != nil {
		t.Fatalf("unpack output: %v", err)
	}
	if scan.GetScanner() != "mock" || !scan.GetPassedGate() {
		t.Fatalf("scan output = scanner %q passed %v, want mock true", scan.GetScanner(), scan.GetPassedGate())
	}

	wrongConfig, err := anypb.New(&contracts.SASTScanConfig{Scanner: "mock"})
	if err != nil {
		t.Fatalf("pack wrong config: %v", err)
	}
	if _, err := provider.CreateTypedModule("security.scanner", "scanner", wrongConfig); err == nil {
		t.Fatal("CreateTypedModule accepted wrong typed config")
	}

	wrongInput, err := anypb.New(&contracts.ScanContainerRequest{Scanner: "mock"})
	if err != nil {
		t.Fatalf("pack wrong input: %v", err)
	}
	if _, err := invoker.InvokeTypedMethod("ScanSAST", wrongInput); err == nil {
		t.Fatal("InvokeTypedMethod accepted wrong typed input")
	}
}

func TestTypedSASTStepCurrentOverridesInputAndConfig(t *testing.T) {
	result, err := typedSASTScan()(context.Background(), sdk.TypedStepRequest[*contracts.SASTScanConfig, *contracts.SASTScanInput]{
		Config: &contracts.SASTScanConfig{
			Scanner:    "config-scanner",
			SourcePath: "./config",
		},
		Input: &contracts.SASTScanInput{
			Scanner:    "input-scanner",
			SourcePath: "./input",
		},
		Current: map[string]any{
			"scanner":     "mock",
			"source_path": "./current",
		},
	})
	if err != nil {
		t.Fatalf("typedSASTScan: %v", err)
	}
	if result == nil || result.Output == nil {
		t.Fatal("expected typed output")
	}
	if got := result.Output.GetScanner(); got != "mock" {
		t.Fatalf("scanner = %q, want current override mock", got)
	}
}

func TestTypedContainerStepRejectsUnsupportedScanner(t *testing.T) {
	_, err := typedContainerScan()(context.Background(), sdk.TypedStepRequest[*contracts.ContainerScanConfig, *contracts.ContainerScanInput]{
		Input: &contracts.ContainerScanInput{Scanner: "grype", TargetImage: "example:latest"},
	})
	if err == nil {
		t.Fatal("typedContainerScan accepted unsupported container scanner")
	}
}

func TestTypedContainerStepPreservesExplicitFalseInput(t *testing.T) {
	values := mergeConfigs(
		containerConfigToMap(&contracts.ContainerScanConfig{IgnoreUnfixed: true}),
		containerInputToMap(&contracts.ContainerScanInput{IgnoreUnfixed: false}),
	)
	if got, ok := values["ignore_unfixed"].(bool); !ok || got {
		t.Fatalf("ignore_unfixed = %#v, want explicit false override", values["ignore_unfixed"])
	}
}

func TestScanStepDispatchUsesCurrentOverride(t *testing.T) {
	step, err := newScanStep("step.sast_scan", "sast", map[string]any{"scanner": "semgrep"})
	if err != nil {
		t.Fatalf("newScanStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil,
		map[string]any{"scanner": "mock", "source_path": "./current"},
		nil,
		map[string]any{"source_path": "./config"},
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got, _ := result.Output["scanner"].(string); got != "mock" {
		t.Fatalf("scanner = %q, want current override mock", got)
	}
}

func TestScanStepRejectsUnknownScannerForEachStepType(t *testing.T) {
	for _, stepType := range []string{"step.sast_scan", "step.container_scan", "step.deps_scan"} {
		t.Run(stepType, func(t *testing.T) {
			step, err := newScanStep(stepType, "scan", nil)
			if err != nil {
				t.Fatalf("newScanStep: %v", err)
			}
			_, err = step.Execute(context.Background(), nil, nil, map[string]any{"scanner": "typo-scanner"}, nil, nil)
			if err == nil {
				t.Fatal("expected unknown scanner error")
			}
			if !strings.Contains(err.Error(), "unsupported scanner") {
				t.Fatalf("error = %v, want unsupported scanner", err)
			}
		})
	}
}

type manifestContract struct {
	Mode          string `json:"mode"`
	ConfigMessage string `json:"config"`
	InputMessage  string `json:"input"`
	OutputMessage string `json:"output"`
}

func loadManifestContracts(t *testing.T) map[string]manifestContract {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "plugin.contracts.json"))
	if err != nil {
		t.Fatalf("read plugin.contracts.json: %v", err)
	}
	var manifest struct {
		Version   string `json:"version"`
		Contracts []struct {
			Kind        string `json:"kind"`
			Type        string `json:"type"`
			ServiceName string `json:"serviceName"`
			Method      string `json:"method"`
			manifestContract
		} `json:"contracts"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse plugin.contracts.json: %v", err)
	}
	if manifest.Version != "v1" {
		t.Fatalf("plugin.contracts.json version = %q, want v1", manifest.Version)
	}
	contracts := make(map[string]manifestContract, len(manifest.Contracts))
	for _, contract := range manifest.Contracts {
		if contract.Mode != "strict" {
			t.Fatalf("%s mode = %q, want strict", contract.Type, contract.Mode)
		}
		var key string
		switch contract.Kind {
		case "module":
			key = "module:" + contract.Type
		case "step":
			key = "step:" + contract.Type
		case "service_method":
			key = "service:" + contract.ServiceName + "/" + contract.Method
		default:
			t.Fatalf("unexpected contract kind %q in plugin.contracts.json", contract.Kind)
		}
		if _, exists := contracts[key]; exists {
			t.Fatalf("duplicate contract %q in plugin.contracts.json", key)
		}
		contracts[key] = contract.manifestContract
	}
	return contracts
}

func contractKey(contract *pb.ContractDescriptor) string {
	switch contract.Kind {
	case pb.ContractKind_CONTRACT_KIND_MODULE:
		return "module:" + contract.ModuleType
	case pb.ContractKind_CONTRACT_KIND_STEP:
		return "step:" + contract.StepType
	case pb.ContractKind_CONTRACT_KIND_SERVICE:
		return "service:" + contract.ServiceName + "/" + contract.Method
	default:
		return contract.Kind.String()
	}
}
