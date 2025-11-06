
package output

import "fmt"

// PrintBanner renderiza o banner do aplicativo para stdout.
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
║   SUITE - Ferramenta Profissional de Caça a Bugs   ║
║   Versão: %s                                   ║
║   https://github.com/GhostN3xus/Huntsuite        ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
`
	fmt.Printf(banner, version)
	fmt.Println("Fique atento. Cace de forma mais inteligente.")
}

// PrintDisclaimer renderiza o aviso legal para stdout.
func PrintDisclaimer() {
	disclaimer := `
AVISO LEGAL: O uso desta ferramenta é para fins educacionais e de pesquisa autorizados
apenas. Não a utilize em sistemas para os quais você não tem permissão explícita.
O uso indevido desta ferramenta pode levar a consequências legais.
Os desenvolvedores não assumem nenhuma responsabilidade e não são responsáveis por
qualquer uso indevido ou dano causado por este programa.
`
	fmt.Println(disclaimer)
}
