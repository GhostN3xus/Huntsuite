
package payloads

import (
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

// CMDIPayloadGenerator gera payloads CMDI.
type CMDIPayloadGenerator struct{}

// NewCMDIPayloadGenerator cria um novo gerador de payload CMDI.
func NewCMDIPayloadGenerator() *CMDIPayloadGenerator {
	return &CMDIPayloadGenerator{}
}

// Name retorna o nome do gerador de payload.
func (g *CMDIPayloadGenerator) Name() string {
	return "cmdi_basic"
}

// Generate gera uma lista de payloads CMDI.
func (g *CMDIPayloadGenerator) Generate(ctx *modules.TargetContext) ([]modules.Payload, error) {
	payloads := []modules.Payload{
		{Value: "id", Type: "CMDI", Encoding: "URL"},
		{Value: "; id", Type: "CMDI", Encoding: "URL"},
	}
	return payloads, nil
}
