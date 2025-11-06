
package validators

import (
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/modules"
	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

// CMDIValidator valida vulnerabilidades de CMDI.
type CMDIValidator struct{}

// NewCMDIValidator cria um novo validador de CMDI.
func NewCMDIValidator() *CMDIValidator {
	return &CMDIValidator{}
}

// Name retorna o nome do validador.
func (v *CMDIValidator) Name() string {
	return "cmdi_validator"
}

// Validate analisa uma resposta para validar uma vulnerabilidade de CMDI.
func (v *CMDIValidator) Validate(resp *modules.ResponsePayload, interaction *oob.Interaction) (bool, error) {
	if strings.Contains(string(resp.Body), "uid=") {
		return true, nil
	}
	return false, nil
}
