
package cmd

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/GhostN3xus/Huntsuite/pkg/report"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Gera relatórios para os resultados da verificação",
	Long:  `Gera relatórios para os resultados da verificação.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		scanID, _ := cmd.Flags().GetInt64("scan-id")
		outputDir, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")

		if scanID == 0 {
			return errors.New("--scan-id é obrigatório")
		}

		scan, err := store.GetScan(context.Background(), scanID)
		if err != nil {
			return err
		}

		target, err := store.GetTarget(context.Background(), scan.TargetID)
		if err != nil {
			return err
		}

		findings, err := store.FindingsByScan(context.Background(), scanID)
		if err != nil {
			return err
		}

		dir := outputDir
		if dir == "" {
			dir = filepath.Join(cfg.General.DataDir, "reports")
		}

		formatVal := strings.ToLower(strings.TrimSpace(format))
		var (
			path   string
			genErr error
		)
		switch formatVal {
		case "markdown", "md":
			path, genErr = report.WriteMarkdownReport(dir, scan, target, findings)
		case "html":
			path, genErr = report.WriteHTMLReport(dir, scan, target, findings)
		case "json":
			path, genErr = report.WriteJSONScanReport(dir, scan, target, findings)
		default:
			return fmt.Errorf("formato de relatório não suportado: %s", formatVal)
		}
		if genErr != nil {
			return genErr
		}
		fmt.Println("Relatório salvo em", path)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().Int64("scan-id", 0, "Identificador da verificação")
	reportCmd.Flags().StringP("output", "o", "", "Diretório de saída para o relatório")
	reportCmd.Flags().StringP("format", "f", "markdown", "Formato do relatório (markdown|html|json)")
}
