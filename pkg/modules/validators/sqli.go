
package validators

import (
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/modules"
	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

// SQLiValidator valida vulnerabilidades de SQLi.
type SQLiValidator struct{}

// NewSQLiValidator cria um novo validador de SQLi.
func NewSQLiValidator() *SQLiValidator {
	return &SQLiValidator{}
}

// Name retorna o nome do validador.
func (v *SQLiValidator) Name() string {
	return "sqli_validator"
}

// Validate analisa uma resposta para validar uma vulnerabilidade de SQLi.
func (v *SQLiValidator) Validate(resp *modules.ResponsePayload, interaction *oob.Interaction) (bool, error) {
	keywords := []string{"sql syntax", "mysql", "postgres", "near ", "syntax error", "odbc", "warning"}
	lower := strings.ToLower(string(resp.Body))
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true, nil
		}
	}
	return false, nil
}
