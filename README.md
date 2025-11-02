# HuntSuite

![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?logo=go&logoColor=white)
![Status](https://img.shields.io/badge/status-scaffold-blueviolet)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

> Plataforma-oficina para montar pipelines ofensivos de bug hunting, com scanners modulares, relatórios ricos e integrações rápidas.

---

## Sumário

1. [Visão geral](#visão-geral)
2. [Destaques rápidos](#destaques-rápidos)
3. [Primeiros passos](#primeiros-passos)
4. [Fluxo ponta a ponta (exemplo real)](#fluxo-ponta-a-ponta-exemplo-real)
5. [Guia de módulos com exemplos](#guia-de-módulos-com-exemplos)
6. [Estrutura do repositório](#estrutura-do-repositório)
7. [Payloads, wordlists e dados persistidos](#payloads-wordlists-e-dados-persistidos)
8. [Boas práticas e próximos passos](#boas-práticas-e-próximos-passos)

---

## Visão geral

HuntSuite nasceu como um **scaffold em Go** para acelerar a construção de pipelines de pentest ofensivo. A aplicação combina discovery de superfície de ataque, gerenciamento de payloads, registro estruturado de requisições/respostas e geração de relatórios (Markdown, HTML e JSON). Todo o código foi escrito para ser **legível e extensível**, permitindo que você plugue motores reais (Subfinder, Interactsh, Chromedp, etc.) conforme evolui sua stack.

A base já inclui:

- Orquestrador de scans que persiste alvos, requisições, respostas e achados.
- Repositório embutido de payloads XSS/SQLi/SSRF com suporte a diretórios externos.
- Relatórios HTML com visual moderno, Markdown pronto para colar no ticket e JSON para integrações.
- Logger estruturado com níveis dinâmicos (debug/verbose/quiet) + rotação de arquivo.
- Integração opcional com Telegram para alertas automáticos.
- CLI única (`huntsuite`) para controlar todo o fluxo.

## Destaques rápidos

| Tema | O que já está pronto | Como evoluir |
| ---- | -------------------- | ------------ |
| **Scanners** | Descoberta automática de parâmetros (query, forms, JSON) e injeção de payloads com controle de cabeçalhos e User-Agent. | Implementar avaliadores específicos (SQL boolean/time-based, SSRF OOB real, etc.). |
| **Persistência** | `pkg/storage/sqlite` em JSON transacional com IDs auto-incrementais e dumps formatados. | Migrar para SQLite real ou Postgres mantendo a interface. |
| **Relatórios** | Markdown, JSON e HTML escuro responsivo com badges de severidade e cards de resumo. | Adicionar exportação PDF ou dashboards adicionais. |
| **Operação** | Config central em `~/.huntsuite/config.yaml`, banner temático, logger colorido e cancelamento via sinais. | Acrescentar modos daemon (`/scan`, `/status`) e rate-limit distribuído. |

> 💡 **Dica:** todo pacote foi desenhado para ser usado isoladamente. Você pode importar `pkg/report` ou `pkg/proxy` em outras ferramentas sem carregar o restante do projeto.

## Primeiros passos

### Requisitos

- Go 1.20 ou superior.
- Acesso a rede (HTTP/DNS) para aproveitar recon e scanners.
- Opcional: binário `interactsh-client` ou similar no `PATH` para validações OOB reais.

### Instalação e build

```bash
# Resolver dependências e baixar payloads opcionais
go mod tidy

# Compilar o binário principal
make build

# Exibir ajuda global e por comando
./huntsuite --help
./huntsuite scan --help
```

### Configuração inicial

A primeira execução cria `~/.huntsuite/config.yaml` com valores padrão. O arquivo é totalmente editável e suporta cabeçalhos customizados para o motor de scan.

```yaml
general:
  data_dir: "/root/.huntsuite/data"
  proxy: ""
database:
  path: "/root/.huntsuite/data/huntsuite.db"
  auto_migrate: true
logging:
  level: "info"
  console_level: "info"
  file_enabled: true
  file_path: "/root/.huntsuite/logs/huntsuite.log"
  max_size_mb: 10
  max_backups: 5
  color: true
scanning:
  timeout_seconds: 20
  threads: 4
  rate_limit_per_host: 0
  user_agent: "HuntSuite/1.0"
  request_delay: "0s"
  headers: ""
output:
  enable_color: true
notifications:
  telegram_token: ""
  telegram_chat_id: ""
```

Para aplicar cabeçalhos globais, basta preencher `scanning.headers` com pares separados por vírgula (ex.: `X-Account=bugbounty, Authorization=Bearer ...`).

## Fluxo ponta a ponta (exemplo real)

1. **Executar o scan**

   ```bash
   go run ./cmd/huntsuite --quiet scan --target https://example.com --scanners xss
   ```

   Saída observada no ambiente de referência (rede restrita):

   ```text
   [02:30:11] ERR scan failed
       error=engine: resolve target: engine: probe target https://example.com: Get "https://example.com": Forbidden
   error: engine: resolve target: engine: probe target https://example.com: Get "https://example.com": Forbidden
   ```

   > ⚠️ Se você estiver em rede corporativa ou laboratório sem saída direta, configure o proxy em `~/.huntsuite/config.yaml` ou use `--proxy` no comando.

2. **Listar achados do scan**

   ```bash
   go run ./cmd/huntsuite findings --scan-id 1
   ```

   Caso o scan ainda não tenha resultados persistidos:

   ```text
   No findings recorded for this scan.
   ```

   Quando existirem achados, a CLI imprime uma tabela `Severity / Type / Title / Evidence` e registra um log informativo.

3. **Gerar relatório (Markdown, HTML ou JSON)**

   ```bash
   go run ./cmd/huntsuite report --scan-id 1 --format html
   ```

   - Em caso de ID inexistente, o comando retorna `error: scan 1 not found`.
   - Para scans válidos, o arquivo é salvo em `<data_dir>/reports/scan-<id>-report.<ext>` e o logger confirma o caminho final.

   O modelo HTML ganhou um layout dark responsivo, com cards de resumo e badges gradientes por severidade — perfeito para anexar em relatórios executivos.

## Guia de módulos com exemplos

Cada pacote foi pensado para ser reutilizado. Abaixo estão mini-snippets de uso e dicas práticas.

### `pkg/scanner`

```go
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
defer cancel()

engine := scanner.NewEngine(store, logger, &http.Client{Timeout: 15 * time.Second})
opts := scanner.Options{
    Target:    "https://target.tld",
    EnableXSS: true,
    Headers:   http.Header{"X-Lab": {"training"}},
}

if err := engine.Run(ctx, opts); err != nil {
    logger.Error("scan failed", logging.Fields{"error": err})
}
```

- **Injeção uniforme**: `runXSS`, `runSQLi` e `runSSRF` compartilham a mesma assinatura (`func (ctx context.Context, scanID int64, target *url.URL, opts Options)`), facilitando a criação de novos módulos.
- **Persistência automática**: cada requisição/resposta é gravada via `store.RecordRequest/RecordResponse`, respeitando limite de 2 MB por corpo.

### `pkg/recon`

```go
r := recon.NewSimpleRecon()
subdomains := r.EnumSubdomains("example.com", "", 5)
fmt.Println("hosts resolvidos:", subdomains)
```

- Por padrão, procura `wordlists/subdomains.txt` relativo ao binário. Ao executar via `go run`, aponte `--wordlist` manualmente para evitar o aviso `wordlist not found`.

### `pkg/mapper`

```go
mapper := mapper.NewSiteMapper()
mapper.Crawl("https://intranet.local", 8*time.Second)
```

- Limita-se ao host inicial, respeita o timeout fornecido e registra tamanho das respostas via `log.Printf`.
- É ideal para mapear entradas antes de alimentar o engine de scanner.

### `pkg/proxy`

```go
cfg := proxy.ProxyConfig{
    ListenAddr: ":8080",
    InjectPayload: func(req *http.Request) {
        if strings.Contains(req.URL.RawQuery, "q=") {
            q := req.URL.Query()
            q.Set("q", q.Get("q")+"' OR '1'='1")
            req.URL.RawQuery = q.Encode()
        }
    },
}
log.Fatal(proxy.StartForwardProxy(cfg))
```

- Implementa CONNECT e pode atuar como proxy local para fuzzing manual.
- Encaixe um MITM ou gravação de tráfego apenas alterando a função `InjectPayload`.

### `pkg/report`

```go
path, err := report.WriteHTMLReport("reports", scan, target, findings)
if err == nil {
    fmt.Println("Relatório salvo em", path)
}
```

- Gera HTML dark com cards e badges gradientes, Markdown com narrativa orientada a reprodução e JSON estruturado para automações.
- Os templates padronizam impacto e remediação com base no tipo de vulnerabilidade.

### `pkg/notify`

```go
if err := notify.AutoNotify("reports/scan-42-report.md", "Scan 42 finalizado"); err != nil {
    log.Printf("notify error: %v", err)
}
```

- Prioriza variáveis de ambiente e faz fallback para `config.Load()`.
- Usa `multipart` para anexar relatórios diretamente no Telegram.

### `pkg/oob`

```go
client, _ := oob.NewInteractClient()
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go client.PollInteractions(ctx)
```

- Pronto para integração com Interactsh real; atualmente gera domínio stub e simula polling.

### `pkg/storage/sqlite`

```go
store, _ := sqlite.Open(context.Background(), "./data/huntsuite.db")
id, _ := store.CreateScan(ctx, targetID, "running", "xss=1")
```

- Persistência em JSON human-readable (`.tmp` + rename para atomicidade).
- `FindingsByScan`, `RequestsByScan` e `RecordResponse` tornam simples construir dashboards externos.

### `pkg/runtime`

```go
ctx := runtime.WithSignalHandler(context.Background())
<-ctx.Done() // cancela on SIGINT/SIGTERM
```

- Útil para encapsular loops e goroutines (scanners, proxys, etc.).

## Estrutura do repositório

```text
.
├── cmd/huntsuite/        # CLI principal (scan, findings, report)
├── pkg/
│   ├── cli/              # Parsing de flags e orquestração da CLI
│   ├── config/           # Load/save de config YAML com defaults seguros
│   ├── logging/          # Logger estruturado com rotação
│   ├── mapper/, recon/   # Reconhecimento de superfície
│   ├── notify/, oob/     # Integrações externas (Telegram, OOB)
│   ├── report/           # Geradores de artefato (MD/HTML/JSON)
│   ├── scanner/          # Engine e utilidades de payloads
│   └── storage/sqlite/   # Persistência local em JSON
├── payloads/             # Payloads customizáveis (sqli.txt, xss, etc.)
├── wordlists/            # Wordlist base de subdomínios
└── README.md             # Este guia
```

## Payloads, wordlists e dados persistidos

- **Payloads**: adicione arquivos `.txt` em `payloads/`. Cada linha é lida automaticamente e pode conter tokens `{{RAND}}` ou `{{OOB}}`.
- **Wordlists**: substitua `wordlists/subdomains.txt` para adaptar o recon ao seu cenário.
- **Dados do scan**: ficam em `~/.huntsuite/data/huntsuite.db` (JSON). Relatórios são gravados em `~/.huntsuite/data/reports/`.

## Boas práticas e próximos passos

- **Controle de rede**: configure `general.proxy` para ambientes fechados ou use `--proxy` em execuções específicas.
- **Timeouts e cancelamentos**: o engine respeita `context.Context`; aproveite para encadear `WithTimeout`/`WithDeadline` em integrações pesadas.
- **Extensão modular**: novos scanners podem reutilizar `sendAndEvaluate` e o mecanismo de `injectionPoint` sem duplicação.
- **Roadmap sugerido**:
  - Integrar fontes externas (Subfinder, FFUF) e alimentar `scanner.Options` com resultados reais.
  - Acrescentar testes unitários por pacote (`go test ./pkg/scanner`, etc.).
  - Containerizar a aplicação com Docker + volume para `~/.huntsuite`.
  - Implementar API REST (`/scan`, `/report`, `/status`) reutilizando `pkg/cli` como camada de serviço.

Boa caçada! Ajuste, estenda e compartilhe melhorias com a comunidade.
