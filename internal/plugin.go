// Package internal implements the workflow-plugin-security-scanner plugin,
// providing SAST, container, and dependency vulnerability scanning via
// pluggable CLI backends (semgrep, trivy, grype, mock).
package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// securityScannerPlugin implements sdk.PluginProvider and sdk.ModuleProvider.
type securityScannerPlugin struct{}

// NewSecurityScannerPlugin returns a new plugin instance.
func NewSecurityScannerPlugin() sdk.PluginProvider {
	return &securityScannerPlugin{}
}

// Manifest returns plugin metadata.
func (p *securityScannerPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-security-scanner",
		Version:     "1.0.0",
		Author:      "GoCodeAlone",
		Description: "Security scanning via semgrep (SAST), trivy (container/deps), and grype (deps)",
	}
}

// ModuleTypes returns the module type names this plugin provides.
func (p *securityScannerPlugin) ModuleTypes() []string {
	return []string{"security.scanner"}
}

// CreateModule creates a security.scanner module instance.
func (p *securityScannerPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	if typeName != "security.scanner" {
		return nil, fmt.Errorf("security-scanner plugin: unknown module type %q", typeName)
	}
	return newScannerModule(name, config)
}
