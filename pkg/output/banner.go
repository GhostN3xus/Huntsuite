package output

import "fmt"

// PrintBanner renders the application banner to stdout.
func PrintBanner(version string) {
	banner := `
╔═══════════════════════════════════════════════════╗
║                                                   ║
║   ██╗  ██╗██╗   ██╗███╗   ██╗████████╗           ║
║   ██║  ██║██║   ██║████╗  ██║╚══██╔══╝           ║
║   ███████║██║   ██║██╔██╗ ██║   ██║              ║
║   ██╔══██║██║   ██║██║╚██╗██║   ██║              ║
║   ██║  ██║╚██████╔╝██║ ╚████║   ██║              ║
║   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝              ║
║                                                   ║
║   SUITE - Professional Bug Hunting Tool          ║
║   Version: %s                                   ║
║   https://github.com/GhostN3xus/Huntsuite        ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
`
	fmt.Printf(banner, version)
	fmt.Println("Stay sharp. Hunt smarter.")
}
