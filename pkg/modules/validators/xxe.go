
package validators

import (
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/modules"
	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

// XXEValidator valida vulnerabilidades de XXE.
type XXEValidator struct{}

// NewXXEValidator cria um novo validador de XXE.
func NewXXEValidator() *XXEValidator {
	return &XXEValidator{}
}

// Name retorna o nome do validador.
func (v *XXEValidator) Name() string {
	return "xxe_validator"
}

// Validate analisa uma resposta para validar uma vulnerabilidade de XXE.
func (v *XXEValidator) Validate(resp *modules.ResponsePayload, interaction *oob.Interaction) (bool, error) {
	if strings.Contains(string(resp.Body), "root:x:0:0:") {
		return true, nil
	}
	return false, nil
}
