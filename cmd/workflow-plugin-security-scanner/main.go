// Command workflow-plugin-security-scanner is a workflow engine external plugin
// that provides security scanning via semgrep (SAST), trivy (container/deps),
// and grype (deps). It runs as a subprocess and communicates with the host
// workflow engine via the go-plugin gRPC protocol.
package main

import (
	"github.com/GoCodeAlone/workflow-plugin-security-scanner/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewSecurityScannerPlugin())
}
