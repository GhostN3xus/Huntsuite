
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/GhostN3xus/Huntsuite/pkg/logging"
	"github.com/GhostN3xus/Huntsuite/pkg/recon"
	"github.com/spf13/cobra"
)

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Executa o reconhecimento em um domínio",
	Long:  `Executa o reconhecimento de subdomínio em um determinado domínio.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, _ := cmd.Flags().GetString("domain")
		wordlist, _ := cmd.Flags().GetString("wordlist")
		output, _ := cmd.Flags().GetString("output")
		threads, _ := cmd.Flags().GetInt("threads")

		if domain == "" {
			return errors.New("o domínio é obrigatório (use -d ou --domain)")
		}

		logger.Info("reconnaissance starting", logging.Fields{"domain": domain, "threads": threads})

		reconEngine := recon.NewSimpleRecon()

		subdomains := reconEngine.EnumSubdomains(domain, wordlist, 120)

		logger.Info("reconnaissance completed", logging.Fields{
			"domain":     domain,
			"subdomains": len(subdomains),
		})

		if len(subdomains) == 0 {
			logger.Warn("no subdomains discovered", logging.Fields{})
			fmt.Println("Nenhum subdomínio descoberto")
			return nil
		}

		fmt.Printf("\nDescobertos %d subdomínios para %s:\n", len(subdomains), domain)
		for _, sub := range subdomains {
			fmt.Printf("  - %s\n", sub)
		}

		if output != "" {
			logger.Info("exporting subdomains to file", logging.Fields{"path": output})
			file, err := os.Create(output)
			if err != nil {
				logger.Error("failed to create output file", logging.Fields{"error": err})
				return err
			}
			defer file.Close()

			for _, sub := range subdomains {
				if _, err := fmt.Fprintln(file, sub); err != nil {
					logger.Error("failed to write subdomain", logging.Fields{"error": err})
					return err
				}
			}
			logger.Info("subdomains exported successfully", logging.Fields{"count": len(subdomains), "path": output})
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(reconCmd)
	reconCmd.Flags().StringP("domain", "d", "", "Domínio do alvo para o reconhecimento")
	reconCmd.Flags().StringP("wordlist", "w", "", "Caminho da lista de palavras personalizada para a enumeração de subdomínios")
	reconCmd.Flags().StringP("output", "o", "", "Arquivo de saída para os subdomínios")
	reconCmd.Flags().IntP("threads", "t", 10, "Número de threads de resolução de DNS simultâneas")
}
