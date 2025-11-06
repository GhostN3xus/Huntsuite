
package validators

import (
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/modules"
	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

// LFIValidator valida vulnerabilidades de LFI.
type LFIValidator struct{}

// NewLFIValidator cria um novo validador de LFI.
func NewLFIValidator() *LFIValidator {
	return &LFIValidator{}
}

// Name retorna o nome do validador.
func (v *LFIValidator) Name() string {
	return "lfi_validator"
}

// Validate analisa uma resposta para validar uma vulnerabilidade de LFI.
func (v *LFIValidator) Validate(resp *modules.ResponsePayload, interaction *oob.Interaction) (bool, error) {
	if strings.Contains(string(resp.Body), "root:x:0:0:") {
		return true, nil
	}
	return false, nil
}
