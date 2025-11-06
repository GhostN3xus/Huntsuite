
package cmd

import (
	"errors"
	"fmt"

	"github.com/GhostN3xus/Huntsuite/pkg/validator"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Valida um único endpoint",
	Long:  `Dispara uma sonda OOB para validar um único endpoint.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		param, _ := cmd.Flags().GetString("param")
		oob, _ := cmd.Flags().GetBool("oob")

		if target == "" {
			return errors.New("o alvo é obrigatório (use -u ou --target)")
		}

		if !oob {
			return errors.New("--oob é obrigatório para validação")
		}

		if param == "" {
			return errors.New("--param é obrigatório para validação")
		}

		store, err := validator.InitDB("")
		if err != nil {
			return err
		}

		finding, err := validator.ProbeSSRF(store, target, param)
		if err != nil {
			return err
		}

		if finding != nil {
			fmt.Printf("Validação bem-sucedida. Descoberta salva com ID: %d\n", finding.ID)
		} else {
			fmt.Println("Nenhuma descoberta confirmada.")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
	validateCmd.Flags().StringP("target", "u", "", "URL ou host do alvo")
	validateCmd.Flags().StringP("param", "p", "", "Parâmetro para injetar a carga útil OOB")
	validateCmd.Flags().Bool("oob", false, "Ativar validação OOB")
}
