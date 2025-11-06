
package cmd

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestVersionCmd(t *testing.T) {
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs([]string{"version"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out, err := io.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	expected := "huntsuite version 1.0.0"
	if !strings.Contains(string(out), expected) {
		t.Fatalf("expected output to contain %q, got %q", expected, string(out))
	}
}

func TestScanCmd_NoTarget(t *testing.T) {
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs([]string{"scan"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error, but got none")
	}
	expected := "o alvo é obrigatório"
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected error to contain %q, got %q", expected, err.Error())
	}
}

func TestReconCmd_NoDomain(t *testing.T) {
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs([]string{"recon"})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error, but got none")
	}
	expected := "o domínio é obrigatório"
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected error to contain %q, got %q", expected, err.Error())
	}
}
