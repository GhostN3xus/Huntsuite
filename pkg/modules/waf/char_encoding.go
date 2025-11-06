
package waf

import (
	"net/url"
	"html"

	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

// CharEncodingBypasser aplica a codificação de caracteres aos payloads.
type CharEncodingBypasser struct{}

// NewCharEncodingBypasser cria um novo bypasser de codificação de caracteres.
func NewCharEncodingBypasser() *CharEncodingBypasser {
	return &CharEncodingBypasser{}
}

// Name retorna o nome do bypasser de WAF.
func (b *CharEncodingBypasser) Name() string {
	return "char_encoding"
}

// Bypass aplica a codificação de URL ou HTML a um payload.
func (b *CharEncodingBypasser) Bypass(payload *modules.Payload) (*modules.Payload, error) {
	encodedPayload := *payload
	switch payload.Encoding {
	case "URL":
		encodedPayload.Value = url.QueryEscape(payload.Value)
	case "HTML":
		encodedPayload.Value = html.EscapeString(payload.Value)
	}
	return &encodedPayload, nil
}
