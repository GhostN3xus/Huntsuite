
package payloads

import (
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

// OpenRedirectPayloadGenerator gera payloads Open Redirect.
type OpenRedirectPayloadGenerator struct{}

// NewOpenRedirectPayloadGenerator cria um novo gerador de payload Open Redirect.
func NewOpenRedirectPayloadGenerator() *OpenRedirectPayloadGenerator {
	return &OpenRedirectPayloadGenerator{}
}

// Name retorna o nome do gerador de payload.
func (g *OpenRedirectPayloadGenerator) Name() string {
	return "open_redirect_basic"
}

// Generate gera uma lista de payloads Open Redirect.
func (g *OpenRedirectPayloadGenerator) Generate(ctx *modules.TargetContext) ([]modules.Payload, error) {
	payloads := []modules.Payload{
		{Value: "https://evil.com", Type: "Open Redirect", Encoding: "URL"},
		{Value: "/evil.com", Type: "Open Redirect", Encoding: "URL"},
	}
	return payloads, nil
}
