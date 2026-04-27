// Package internal implements the workflow-plugin-security-scanner plugin,
// providing SAST, container, and dependency vulnerability scanning via
// pluggable CLI backends (semgrep, trivy, grype, mock).
package internal

import (
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-security-scanner/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-security-scanner/internal.Version=X.Y.Z".
// Default is a bare semver so plugin loaders that validate semver accept
// unreleased dev builds; goreleaser overrides with the real release tag.
var Version = "0.0.0"

// securityScannerPlugin implements sdk.PluginProvider and strict contract providers.
type securityScannerPlugin struct{}

var moduleTypes = []string{"security.scanner"}
var stepTypes = []string{"step.sast_scan", "step.container_scan", "step.deps_scan"}

// NewSecurityScannerPlugin returns a new plugin instance.
func NewSecurityScannerPlugin() sdk.PluginProvider {
	return &securityScannerPlugin{}
}

// Manifest returns plugin metadata.
func (p *securityScannerPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-security-scanner",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Security scanning via semgrep (SAST), trivy (container/deps), and grype (deps)",
	}
}

// ModuleTypes returns the module type names this plugin provides.
func (p *securityScannerPlugin) ModuleTypes() []string {
	return append([]string(nil), moduleTypes...)
}

// TypedModuleTypes returns the strict module type names this plugin provides.
func (p *securityScannerPlugin) TypedModuleTypes() []string {
	return append([]string(nil), moduleTypes...)
}

// CreateModule creates a security.scanner module instance.
func (p *securityScannerPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	if typeName != "security.scanner" {
		return nil, fmt.Errorf("security-scanner plugin: unknown module type %q", typeName)
	}
	return newScannerModule(name, config)
}

// CreateTypedModule creates a security.scanner module from protobuf config.
func (p *securityScannerPlugin) CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error) {
	factory := sdk.NewTypedModuleFactory("security.scanner", &contracts.ScannerModuleConfig{}, func(name string, cfg *contracts.ScannerModuleConfig) (sdk.ModuleInstance, error) {
		return newScannerModule(name, scannerModuleConfigToMap(cfg))
	})
	return factory.CreateTypedModule(typeName, name, config)
}

// StepTypes returns the step type names this plugin provides.
func (p *securityScannerPlugin) StepTypes() []string {
	return append([]string(nil), stepTypes...)
}

// TypedStepTypes returns the strict step type names this plugin provides.
func (p *securityScannerPlugin) TypedStepTypes() []string {
	return append([]string(nil), stepTypes...)
}

// CreateStep creates a scan step instance.
func (p *securityScannerPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	return newScanStep(typeName, name, config)
}

// CreateTypedStep creates a protobuf-typed scan step instance.
func (p *securityScannerPlugin) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.sast_scan":
		factory := sdk.NewTypedStepFactory(typeName, &contracts.SASTScanConfig{}, &contracts.SASTScanInput{}, typedSASTScan())
		return factory.CreateTypedStep(typeName, name, config)
	case "step.container_scan":
		factory := sdk.NewTypedStepFactory(typeName, &contracts.ContainerScanConfig{}, &contracts.ContainerScanInput{}, typedContainerScan())
		return factory.CreateTypedStep(typeName, name, config)
	case "step.deps_scan":
		factory := sdk.NewTypedStepFactory(typeName, &contracts.DepsScanConfig{}, &contracts.DepsScanInput{}, typedDepsScan())
		return factory.CreateTypedStep(typeName, name, config)
	default:
		return nil, fmt.Errorf("security-scanner plugin: unknown step type %q", typeName)
	}
}

// ContractRegistry returns protobuf descriptors and strict contract metadata.
func (p *securityScannerPlugin) ContractRegistry() *pb.ContractRegistry {
	return &pb.ContractRegistry{
		FileDescriptorSet: &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(contracts.File_internal_contracts_security_scanner_proto),
		}},
		Contracts: []*pb.ContractDescriptor{
			moduleContract("security.scanner", "ScannerModuleConfig"),
			stepContract("step.sast_scan", "SASTScanConfig", "SASTScanInput", "ScanOutput"),
			stepContract("step.container_scan", "ContainerScanConfig", "ContainerScanInput", "ScanOutput"),
			stepContract("step.deps_scan", "DepsScanConfig", "DepsScanInput", "ScanOutput"),
			serviceContract("security.scanner", "ScanSAST", "ScanSASTRequest", "ScanOutput"),
			serviceContract("security.scanner", "ScanContainer", "ScanContainerRequest", "ScanOutput"),
			serviceContract("security.scanner", "ScanDeps", "ScanDepsRequest", "ScanOutput"),
		},
	}
}

func moduleContract(moduleType, configMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.security_scanner.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_MODULE,
		ModuleType:    moduleType,
		ConfigMessage: pkg + configMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func stepContract(stepType, configMessage, inputMessage, outputMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.security_scanner.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: pkg + configMessage,
		InputMessage:  pkg + inputMessage,
		OutputMessage: pkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func serviceContract(moduleType, method, inputMessage, outputMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.security_scanner.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_SERVICE,
		ModuleType:    moduleType,
		ServiceName:   moduleType,
		Method:        method,
		InputMessage:  pkg + inputMessage,
		OutputMessage: pkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}
