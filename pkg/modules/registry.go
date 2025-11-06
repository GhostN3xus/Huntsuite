
package modules

import "fmt"

// Registry gerencia os módulos disponíveis.
var Registry *ModuleRegistry

// ModuleRegistry gerencia os módulos disponíveis.
type ModuleRegistry struct {
	PayloadGenerators     map[string]PayloadGenerator
	WAFBypassers          map[string]WAFBypasser
	VulnerabilityValidators map[string]VulnerabilityValidator
}

// NewRegistry cria um novo registro de módulo.
func NewRegistry() *ModuleRegistry {
	return &ModuleRegistry{
		PayloadGenerators:     make(map[string]PayloadGenerator),
		WAFBypassers:          make(map[string]WAFBypasser),
		VulnerabilityValidators: make(map[string]VulnerabilityValidator),
	}
}

// RegisterPayloadGenerator registra um novo gerador de payload.
func (r *ModuleRegistry) RegisterPayloadGenerator(gen PayloadGenerator) error {
	if _, exists := r.PayloadGenerators[gen.Name()]; exists {
		return fmt.Errorf("gerador de payload %s já registrado", gen.Name())
	}
	r.PayloadGenerators[gen.Name()] = gen
	return nil
}

// RegisterWAFBypasser registra um novo bypasser de WAF.
func (r *ModuleRegistry) RegisterWAFBypasser(bypasser WAFBypasser) error {
	if _, exists := r.WAFBypassers[bypasser.Name()]; exists {
		return fmt.Errorf("bypasser de WAF %s já registrado", bypasser.Name())
	}
	r.WAFBypassers[bypasser.Name()] = bypasser
	return nil
}

// RegisterVulnerabilityValidator registra um novo validador de vulnerabilidade.
func (r *ModuleRegistry) RegisterVulnerabilityValidator(validator VulnerabilityValidator) error {
	if _, exists := r.VulnerabilityValidators[validator.Name()]; exists {
		return fmt.Errorf("validador de vulnerabilidade %s já registrado", validator.Name())
	}
	r.VulnerabilityValidators[validator.Name()] = validator
	return nil
}

// GetPayloadGenerator recupera um gerador de payload pelo nome.
func (r *ModuleRegistry) GetPayloadGenerator(name string) (PayloadGenerator, bool) {
	gen, ok := r.PayloadGenerators[name]
	return gen, ok
}

// GetWAFBypasser recupera um bypasser de WAF pelo nome.
func (r *ModuleRegistry) GetWAFBypasser(name string) (WAFBypasser, bool) {
	bypasser, ok := r.WAFBypassers[name]
	return bypasser, ok
}

// GetVulnerabilityValidator recupera um validador de vulnerabilidade pelo nome.
func (r *ModuleRegistry) GetVulnerabilityValidator(name string) (VulnerabilityValidator, bool) {
	validator, ok := r.VulnerabilityValidators[name]
	return validator, ok
}
