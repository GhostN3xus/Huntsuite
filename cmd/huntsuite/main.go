package main

import (
	"fmt"
	"os"

	"github.com/GhostN3xus/Huntsuite/pkg/cli"
)

// Version is set at compile time via ldflags
var Version = "dev"

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
