
package main

import (
	"github.com/GhostN3xus/Huntsuite/pkg/cli/cmd"
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
	"github.com/GhostN3xus/Huntsuite/pkg/modules/payloads"
	"github.com/GhostN3xus/Huntsuite/pkg/modules/validators"
	"github.com/GhostN3xus/Huntsuite/pkg/modules/waf"
)

// A versão é definida em tempo de compilação através de ldflags
var Version = "dev"

func main() {
	// Inicializa o registro de módulos e registra os módulos disponíveis
	modules.Registry = modules.NewRegistry()
	modules.Registry.RegisterPayloadGenerator(payloads.NewXSSPayloadGenerator())
	modules.Registry.RegisterWAFBypasser(waf.NewCharEncodingBypasser())
	modules.Registry.RegisterVulnerabilityValidator(validators.NewSSRFValidator())

	cmd.Execute()
}
