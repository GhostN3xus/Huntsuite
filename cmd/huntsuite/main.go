
package main

import (
	"github.com/GhostN3xus/Huntsuite/pkg/cli/cmd"
)

// A versão é definida em tempo de compilação através de ldflags
var Version = "dev"

func main() {
	cmd.Execute()
}
