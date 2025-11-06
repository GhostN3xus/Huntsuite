
package waf

import (
	"testing"

	"github.com/GhostN3xus/Huntsuite/pkg/modules"
)

func TestCharEncodingBypasser(t *testing.T) {
	bypasser := NewCharEncodingBypasser()

	// Teste de codificação de URL
	payload := &modules.Payload{Value: "<script>", Encoding: "URL"}
	encodedPayload, err := bypasser.Bypass(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "%3Cscript%3E"
	if encodedPayload.Value != expected {
		t.Errorf("expected %q, got %q", expected, encodedPayload.Value)
	}

	// Teste de codificação de HTML
	payload = &modules.Payload{Value: "<script>", Encoding: "HTML"}
	encodedPayload, err = bypasser.Bypass(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected = "&lt;script&gt;"
	if encodedPayload.Value != expected {
		t.Errorf("expected %q, got %q", expected, encodedPayload.Value)
	}
}
