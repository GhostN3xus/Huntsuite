
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/config"
	"github.com/GhostN3xus/Huntsuite/pkg/logging"
	"github.com/GhostN3xus/Huntsuite/pkg/output"
	pkgRuntime "github.com/GhostN3xus/Huntsuite/pkg/runtime"
	"github.com/GhostN3xus/Huntsuite/pkg/storage/sqlite"
	"github.com/spf13/cobra"
)

var (
	cfg        *config.Config
	logger     *logging.Logger
	store      *sqlite.Store
	httpClient *http.Client
	version    = "1.0.0"
)

var rootCmd = &cobra.Command{
	Use:   "huntsuite",
	Short: "HuntSuite é uma ferramenta de automação ofensiva.",
	Long:  `HuntSuite é um mecanismo de automação ofensiva focado em reconhecimento e validação de alto sinal.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Não execute para comandos de ajuda ou versão
		if cmd.Name() == "help" || cmd.Name() == "version" {
			return nil
		}

		configPath, _ := cmd.Flags().GetString("config")
		quiet, _ := cmd.Flags().GetBool("quiet")
		verbose, _ := cmd.Flags().GetBool("verbose")
		debug, _ := cmd.Flags().GetBool("debug")

		var err error
		cfg, _, err = config.Load(configPath)
		if err != nil {
			return err
		}

		runtimeOpts := logging.RuntimeOptions{Quiet: quiet, Verbose: verbose, Debug: debug}
		logger, err = logging.NewLogger(cfg.Logging, runtimeOpts)
		if err != nil {
			return err
		}

		if !quiet {
			output.PrintBanner(version)
		}

		ctx := pkgRuntime.WithSignalHandler(context.Background())
		store, err = sqlite.Open(ctx, cfg.Database.Path)
		if err != nil {
			return err
		}

		httpClient = &http.Client{Timeout: time.Duration(cfg.Scanning.TimeoutSeconds) * time.Second}
		if cfg.General.Proxy != "" {
			if proxyURL, err := url.Parse(cfg.General.Proxy); err == nil {
				httpClient.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			} else {
				logger.Warn("proxy inválido da configuração", logging.Fields{"error": err})
			}
		}

		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if logger != nil {
			logger.Close()
		}
		if store != nil {
			store.Close()
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Imprime o número da versão do HuntSuite",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "huntsuite version %s\n", version)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Ocorreu um erro durante a execução da CLI: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.PersistentFlags().String("config", "", "Caminho para o arquivo de configuração")
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Exibir apenas as descobertas e erros")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Log detalhado")
	rootCmd.PersistentFlags().Bool("debug", false, "Log de depuração")
}
