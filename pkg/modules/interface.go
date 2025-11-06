
package modules

import (
	"net/http"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

// TargetContext contém informações sobre o alvo que podem ser usadas
// pelos módulos para gerar ou validar payloads.
type TargetContext struct {
	URL        string
	Host       string
	Headers    http.Header
	Body       []byte
	Technology string // por exemplo, "PHP", "Node.js", "Apache"
}

// Payload representa uma única carga útil a ser enviada ao alvo.
type Payload struct {
	Value    string // O valor real do payload
	Type     string // por exemplo, "XSS", "SQLi", "SSRF"
	Encoding string // por exemplo, "URL", "HTML", "Base64"
}

// PayloadGenerator define a interface para módulos que geram payloads.
type PayloadGenerator interface {
	// Generate gera uma lista de payloads com base no contexto do alvo.
	Generate(ctx *TargetContext) ([]Payload, error)
	// Name retorna o nome do gerador de payload.
	Name() string
}

// WAFBypasser define a interface para módulos que aplicam técnicas de bypass de WAF.
type WAFBypasser interface {
	// Bypass aplica técnicas de bypass de WAF a um payload.
	Bypass(payload *Payload) (*Payload, error)
	// Name retorna o nome do bypasser de WAF.
	Name() string
}

// VulnerabilityValidator define a interface para módulos que validam vulnerabilidades.
type VulnerabilityValidator interface {
	// Validate analisa uma resposta HTTP ou uma interação OOB para validar uma vulnerabilidade.
	Validate(resp *ResponsePayload, interaction *oob.Interaction) (bool, error)
	// Name retorna o nome do validador.
	Name() string
}

// ResponsePayload é uma cópia da struct responsePayload do pacote scanner.
// Isso é necessário para evitar dependências de importação circular.
type ResponsePayload struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Latency    time.Duration
}
