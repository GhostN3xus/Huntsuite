
package validators

import (
	"github.com/GhostN3xus/Huntsuite/pkg/modules"
	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

// OpenRedirectValidator valida vulnerabilidades de Open Redirect.
type OpenRedirectValidator struct{}

// NewOpenRedirectValidator cria um novo validador de Open Redirect.
func NewOpenRedirectValidator() *OpenRedirectValidator {
	return &OpenRedirectValidator{}
}

// Name retorna o nome do validador.
func (v *OpenRedirectValidator) Name() string {
	return "open_redirect_validator"
}

// Validate analisa uma resposta para validar uma vulnerabilidade de Open Redirect.
func (v *OpenRedirectValidator) Validate(resp *modules.ResponsePayload, interaction *oob.Interaction) (bool, error) {
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		location := resp.Headers.Get("Location")
		if location == "https://evil.com" || location == "/evil.com" {
			return true, nil
		}
	}
	return false, nil
}
