
package validators

import (
	"testing"

	"github.com/GhostN3xus/Huntsuite/pkg/oob"
)

func TestSSRFValidator(t *testing.T) {
	validator := NewSSRFValidator()

	// Teste com interação nula
	valid, err := validator.Validate(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected invalid for nil interaction")
	}

	// Teste com interação OOB, mas sem solicitação bruta
	interaction := &oob.Interaction{}
	valid, err = validator.Validate(nil, interaction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected valid for OOB interaction without raw request")
	}

	// Teste com solicitação bruta contendo cabeçalho Via
	interaction = &oob.Interaction{RawRequest: "Via: 1.1 google"}
	valid, err = validator.Validate(nil, interaction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected valid for raw request with Via header")
	}
}
