
package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var findingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Lista os resultados de uma verificação",
	Long:  `Lista os resultados armazenados para uma verificação.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID, _ := cmd.Flags().GetInt64("scan-id")
		if scanID == 0 {
			return errors.New("--scan-id é obrigatório")
		}

		findings, err := store.FindingsByScan(context.Background(), scanID)
		if err != nil {
			return err
		}

		if len(findings) == 0 {
			fmt.Println("Nenhuma descoberta registrada para esta verificação.")
			return nil
		}

		fmt.Println("Gravidade\tTipo\tTítulo\tEvidência")
		for _, f := range findings {
			evidence := ""
			if f.Evidence != nil {
				evidence = *f.Evidence
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", strings.ToUpper(f.Severity), f.Type, f.Title, evidence)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(findingsCmd)
	findingsCmd.Flags().Int64("scan-id", 0, "Identificador da verificação")
}
