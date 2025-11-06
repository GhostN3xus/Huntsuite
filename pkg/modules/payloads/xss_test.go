
package payloads

import (
	"testing"

	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

func TestXSSPayloadGenerator(t *testing.T) {
	gen := NewXSSPayloadGenerator()

	// Teste com contexto nulo
	payloads, err := gen.Generate(&modules.TargetContext{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(payloads) != 3 {
		t.Errorf("expected 3 payloads, got %d", len(payloads))
	}

	// Teste com contexto PHP
	payloads, err = gen.Generate(&modules.TargetContext{Technology: "PHP"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(payloads) != 4 {
		t.Errorf("expected 4 payloads for PHP context, got %d", len(payloads))
	}
}
