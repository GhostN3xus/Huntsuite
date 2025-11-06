
package validators

import (
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/modules"
	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

// SSRFValidator valida vulnerabilidades de SSRF.
type SSRFValidator struct{}

// NewSSRFValidator cria um novo validador de SSRF.
func NewSSRFValidator() *SSRFValidator {
	return &SSRFValidator{}
}

// Name retorna o nome do validador.
func (v *SSRFValidator) Name() string {
	return "ssrf_validator"
}

// Validate analisa uma interação OOB para validar uma vulnerabilidade de SSRF.
func (v *SSRFValidator) Validate(resp *modules.ResponsePayload, interaction *oob.Interaction) (bool, error) {
	if interaction == nil {
		return false, nil
	}

	// Lógica de validação aprimorada: verificar a solicitação bruta para cabeçalhos específicos
	// que podem indicar um proxy ou a origem da solicitação.
	if interaction.RawRequest != "" {
		if strings.Contains(interaction.RawRequest, "Via:") ||
			strings.Contains(interaction.RawRequest, "X-Forwarded-For:") {
			// A presença desses cabeçalhos aumenta a confiança de que o SSRF é real.
			return true, nil
		}
	}

	// Lógica de fallback: se nenhuma solicitação bruta estiver disponível, confie na interação.
	return true, nil
}
