
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
	modules.Registry.RegisterPayloadGenerator(payloads.NewSQLiPayloadGenerator())
	modules.Registry.RegisterPayloadGenerator(payloads.NewLFIPayloadGenerator())
	modules.Registry.RegisterPayloadGenerator(payloads.NewXXEPayloadGenerator())
	modules.Registry.RegisterPayloadGenerator(payloads.NewCMDIPayloadGenerator())
	modules.Registry.RegisterPayloadGenerator(payloads.NewOpenRedirectPayloadGenerator())

	modules.Registry.RegisterWAFBypasser(waf.NewCharEncodingBypasser())

	modules.Registry.RegisterVulnerabilityValidator(validators.NewSSRFValidator())
	modules.Registry.RegisterVulnerabilityValidator(validators.NewSQLiValidator())
	modules.Registry.RegisterVulnerabilityValidator(validators.NewLFIValidator())
	modules.Registry.RegisterVulnerabilityValidator(validators.NewXXEValidator())
	modules.Registry.RegisterVulnerabilityValidator(validators.NewCMDIValidator())
	modules.Registry.RegisterVulnerabilityValidator(validators.NewOpenRedirectValidator())

	cmd.Execute()
}
