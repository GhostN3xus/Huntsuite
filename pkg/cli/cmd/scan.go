
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/GhostN3xus/Huntsuite/pkg/scanner"
	"github.com/GhostN3xus/Huntsuite/pkg/storage/sqlite"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Executa a verificação em um alvo",
	Long:  `Executa a verificação de vulnerabilidades em um determinado alvo.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		scannersArg, _ := cmd.Flags().GetString("scanners")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		oobDomain, _ := cmd.Flags().GetString("oob-domain")
		delay, _ := cmd.Flags().GetDuration("delay")
		proxyOverride, _ := cmd.Flags().GetString("proxy")
		output, _ := cmd.Flags().GetString("output")
		headers, _ := cmd.Flags().GetStringArray("header")

		if target == "" {
			return errors.New("o alvo é obrigatório (use -u ou --target)")
		}

		fullTarget := target
		if !strings.HasPrefix(fullTarget, "http://") && !strings.HasPrefix(fullTarget, "https://") {
			fullTarget = "https://" + fullTarget
		}

		transport := httpClient.Transport
		if proxyOverride != "" {
			proxyURL, err := url.Parse(proxyOverride)
			if err != nil {
				return fmt.Errorf("proxy inválido: %w", err)
			}
			transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}

		localClient := &http.Client{
			Timeout:   time.Duration(timeout) * time.Second,
			Transport: transport,
		}

		engine := scanner.NewEngine(store, logger, localClient)

		combinedHeaders := http.Header{}
		for k, v := range cfg.Scanning.Headers {
			if strings.TrimSpace(k) == "" {
				continue
			}
			combinedHeaders.Set(k, v)
		}

		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				combinedHeaders.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		enabled := make(map[string]bool)
		scannerList := strings.ToLower(strings.TrimSpace(scannersArg))
		if scannerList == "all" {
			enabled["xss"] = true
			enabled["sqli"] = true
			enabled["ssrf"] = true
			enabled["lfi"] = true
			enabled["xxe"] = true
			enabled["cmdi"] = true
			enabled["open-redirect"] = true
		} else {
			tokens := strings.Split(scannerList, ",")
			for _, token := range tokens {
				enabled[strings.TrimSpace(token)] = true
			}
		}

		opts := scanner.Options{
			Target:             fullTarget,
			OOBDomain:          oobDomain,
			EnableXSS:          enabled["xss"],
			EnableSQLi:         enabled["sqli"],
			EnableSSRF:         enabled["ssrf"],
			EnableLFI:          enabled["lfi"],
			EnableXXE:          enabled["xxe"],
			EnableCMDI:         enabled["cmdi"],
			EnableOpenRedirect: enabled["open-redirect"],
			Timeout:            localClient.Timeout,
			UserAgent:          cfg.Scanning.UserAgent,
			Delay:              delay,
			Headers:            combinedHeaders,
			Threads:            threads,
		}

		ctx := context.Background()
		scanID, err := engine.Run(ctx, opts)
		if err != nil {
			return err
		}

		if output != "" {
			findings, err := store.FindingsByScan(ctx, scanID)
			if err != nil {
				return err
			}
			file, err := os.Create(output)
			if err != nil {
				return err
			}
			defer file.Close()
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			return encoder.Encode(findings)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("target", "u", "", "URL ou host do alvo")
	scanCmd.Flags().StringP("scanners", "m", "all", "Lista de scanners a serem executados (xss,sqli,ssrf,lfi,xxe,cmdi,open-redirect)")
	scanCmd.Flags().IntP("threads", "t", 50, "Número de threads simultâneas")
	scanCmd.Flags().Int("timeout", 20, "Tempo limite da solicitação em segundos")
	scanCmd.Flags().String("oob-domain", "", "Domínio fora de banda para validação de SSRF")
	scanCmd.Flags().Duration("delay", 0, "Atraso entre as injeções de payload")
	scanCmd.Flags().StringP("proxy", "p", "", "Substituir o proxy HTTP para esta verificação")
	scanCmd.Flags().StringP("output", "o", "", "Arquivo de saída para as descobertas (JSON)")
	scanCmd.Flags().StringArrayP("header", "H", []string{}, "Cabeçalho da solicitação adicional no formato 'Chave: Valor' (repetível)")
}

func exportFindings(path string, findings []sqlite.Finding) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(findings)
}
