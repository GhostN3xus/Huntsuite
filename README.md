# HuntSuite

HuntSuite é um scaffold escrito em Go para construir uma plataforma de pentest ofensiva. O projeto combina proxy HTTP, enumeração, coleta OOB (out-of-band), geração de relatórios e uma camada simples de validação para findings. O código serve como base extensível: todas as rotinas são deliberadamente simples e funcionam como pontos de partida para integrações mais avançadas.

## Índice rápido
- [Estrutura do repositório](#estrutura-do-repositório)
- [Requisitos](#requisitos)
- [Configuração inicial](#configuração-inicial)
- [CLI `huntsuite`](#cli-huntsuite)
- [Visão geral dos pacotes e funções](#visão-geral-dos-pacotes-e-funções)
- [Wordlists e payloads](#wordlists-e-payloads)
- [Logs e relatórios](#logs-e-relatórios)
- [Trabalhando com notificações](#trabalhando-com-notificações)
- [Próximos passos sugeridos](#próximos-passos-sugeridos)

## Estrutura do repositório
```
.
├── cmd/huntsuite        # CLI principal e roteamento de subcomandos
├── pkg/                 # Bibliotecas internas (core, proxy, recon, etc.)
├── payloads/            # Payloads de teste para fuzzing (SSRF, XSS)
├── wordlists/           # Wordlists de subdomínios utilizadas no recon
├── Makefile             # Atalhos para build/clean
├── go.mod / go.sum      # Dependências Go
└── README.md            # Este guia
```

## Requisitos
- Go 1.20 ou superior (necessário para compilar o projeto)
- Ferramentas opcionais:
  - [`interactsh-client`](https://github.com/projectdiscovery/interactsh) disponível no `PATH` para OOB real
  - Banco SQLite (o driver `github.com/mattn/go-sqlite3` é incorporado via módulo Go)
  - Acesso à Internet para execução de enumeração DNS e crawling

## Configuração inicial
1. **Instale dependências Go** (caso ainda não tenha):
   ```bash
   go mod tidy
   ```
2. **Compile o binário**:
   ```bash
   make build
   ```
3. **Explore os subcomandos**:
   ```bash
   ./huntsuite --help
   ./huntsuite <comando> --help
   ```
4. **(Opcional) Configure notificações Telegram**: salve um arquivo `~/.huntsuite/config.json` via `pkg/config.Save` ou defina as variáveis `HUNTSUITE_TELEGRAM_TOKEN` e `HUNTSUITE_TELEGRAM_CHAT_ID`.

## CLI `huntsuite`
O binário `huntsuite` roteia para diferentes subcomandos. Cada subcomando possui flags próprias definidas com `flag.FlagSet` em `cmd/huntsuite/main.go`.

| Comando      | Flags principais | Descrição |
|--------------|------------------|-----------|
| `proxy`      | `--listen` (endereço para bind, padrão `:8080`), `--inject` (habilita função de injeção stub) | Inicia proxy forward HTTP/HTTPS com suporte a CONNECT e possibilidade de instrumentar requisições antes do envio. Usa `proxy.StartForwardProxy`.
| `oob`        | _sem flags_ | Tenta invocar `interactsh-client`; se indisponível, cria stub via `oob.NewInteractClient` e passa a fazer polling de eventos com `PollInteractions`.
| `recon`      | `--target` (domínio obrigatório), `--wordlist` (opcional) | Enumera subdomínios via `recon.SimpleRecon.EnumSubdomains`. Resultados são persistidos com `report.WriteJSONReport`.
| `map`        | `--target` (URL obrigatória), `--timeout` (segundos) | Executa crawler limitado ao host inicial por meio de `mapper.SiteMapper.Crawl`.
| `scan`       | `--target` (URL/domínio obrigatório), `--oob-domain` (domínio customizado), `--disclosure` (habilita sondas de divulgação) | Dispara `core.Engine.Scan` e, opcionalmente, `disclosure.Probe`.
| `validate`   | `--target` (URL obrigatória), `--param` (nome do parâmetro SSRF), `--db` (arquivo SQLite) | Executa validação SSRF com `validator.ProbeSSRF`, salvando findings no banco e em JSON.

Caso nenhum comando seja informado, o programa exibe uso amigável via `usage()`.

## Visão geral dos pacotes e funções
A tabela abaixo lista todas as funções expostas no projeto, agrupadas por pacote. Funções não-exportadas relevantes também estão incluídas para facilitar extensão.

### `cmd/huntsuite`
- `main()` — analisa argumentos e roteia para os subcomandos acima.
- `usage()` — imprime ajuda básica quando argumentos são inválidos.

### `pkg/config`
- `Save(cfg *Config) error` — persiste arquivo `config.json` em `~/.huntsuite/` com permissões restritivas.
- `Load() (*Config, error)` — carrega o arquivo de configuração; retorna instância vazia se não existir.

### `pkg/core`
- `NewEngine() *Engine` — constrói instância da estrutura de orquestração.
- `(*Engine).Scan(target, oobDomain string)` — fluxo principal de scan; atualmente registra logs simulando etapas e gera mensagem final com nome do relatório.

### `pkg/disclosure`
- `WriteReport(outdir string, findings []Finding)` — serializa findings de disclosure em JSON dentro de `outdir` (padrão `reports/`).
- `Probe(target string, timeoutSeconds int) []Finding` — verifica arquivos sensíveis (`/.env`, `/.git/config`, etc.), coletando trechos e status HTTP.
- `min(a, b int) int` — função auxiliar para limitar tamanho de snippets.

### `pkg/logging`
- `Log(component, level, message string)` — escreve logs em JSON na saída padrão e em `logs/huntsuite.log`.

### `pkg/mapper`
- `NewSiteMapper() *SiteMapper` — fábrica para o crawler.
- `(*SiteMapper).Crawl(start string, timeout time.Duration)` — varre links internos a partir de `start`, respeitando `timeout` para requisições HTTP e expandindo somente URLs do mesmo host.
- `handleConnect`? (não neste pacote; ver `pkg/proxy`).

### `pkg/notify`
- `SendMessage(botToken, chatID, text string) error` — envia mensagem simples via Telegram Bot API (`sendMessage`).
- `SendDocument(botToken, chatID, filePath, caption string) error` — faz upload de arquivo como documento via multipart para o chat especificado.
- `AutoNotify(reportPath, summary string) error` — tenta descobrir credenciais (variáveis de ambiente ou `pkg/config.Load`) e dispara `SendMessage`/`SendDocument` quando disponíveis.

### `pkg/oob`
- `NewInteractClient() (*InteractClient, error)` — gera domínio stub OOB e retorna cliente para polling.
- `(*InteractClient).PollInteractions(ctx context.Context)` — laço simples que simula polling de interações a cada 5 segundos.
- `ExecInteract(ctx context.Context) (string, error)` — procura por binários `interactsh-client`/`interactsh`, executa com `-silent` e retorna domínio emitido.
- `ExecInteractWithTimeout(timeout time.Duration) (string, error)` — helper que invoca `ExecInteract` com `context.WithTimeout`.

### `pkg/proxy`
- `StartForwardProxy(cfg ProxyConfig) error` — inicia servidor HTTP que atua como forward proxy, com logs e hook para injetar payloads.
- `handleConnect(w http.ResponseWriter, r *http.Request)` — (não exportada) implementa túnel TCP para requisições `CONNECT`.

### `pkg/recon`
- `NewSimpleRecon() *SimpleRecon` — fábrica do enumerador.
- `(*SimpleRecon).EnumSubdomains(domain, wordlistPath string, timeoutSeconds int) []string` — resolve subdomínios presentes na wordlist informada (ou default do projeto) e retorna hosts válidos.

### `pkg/report`
- `WriteJSONReport(prefix string, data interface{}) string` — grava artefato JSON com timestamp em `reports/` e dispara `notify.AutoNotify` em goroutine.

### `pkg/validator`
- `InitDB(path string) (*sql.DB, error)` — cria/abre banco SQLite e garante tabela `findings`.
- `SaveFinding(db *sql.DB, f Finding) (int64, error)` — insere finding na tabela e retorna `LastInsertId`.
- `ProbeSSRF(db *sql.DB, target, param string) (*Finding, error)` — gera payload SSRF com domínio OOB, envia requisição, salva finding e reporta resultado em JSON.

## Wordlists e payloads
- `wordlists/subdomains.txt` — lista de subdomínios base utilizada por `pkg/recon`. Substitua ou expanda conforme necessário.
- `payloads/ssrf.txt`, `payloads/xss.txt` — exemplos de payloads que podem alimentar fuzzers ou o proxy (não utilizados automaticamente).

## Logs e relatórios
- **Relatórios JSON**: gerados em `reports/` por `pkg/report` e `pkg/disclosure`. Cada arquivo leva timestamp no nome.
- **Logs estruturados**: o pacote `pkg/logging` grava eventos em `logs/huntsuite.log` no formato JSON. O proxy, mapper e demais componentes também usam `log.Printf` para diagnósticos imediatos.

## Trabalhando com notificações
1. Defina `HUNTSUITE_TELEGRAM_TOKEN` e `HUNTSUITE_TELEGRAM_CHAT_ID`, ou salve o arquivo de configuração com `pkg/config.Save`.
2. Ao gerar um relatório (`report.WriteJSONReport` ou `disclosure.WriteReport`), `pkg/notify.AutoNotify` tentará enviar resumo e arquivo automaticamente.
3. Utilize `notify.SendMessage`/`notify.SendDocument` diretamente em integrações personalizadas quando desejar granularidade maior.

## Próximos passos sugeridos
O scaffold inclui pontos para evolução imediata:
- Integrar clientes reais (Interactsh, Subfinder/Amass, Chromedp) e mover lógicas de stub para implementações completas.
- Adicionar testes automatizados para cada pacote e configurar pipeline CI/CD.
- Evoluir proxy para MITM com geração de CA e interceptação TLS.
- Persistir resultados em banco e construir UI para revisão manual dos findings.
- Expandir biblioteca de validações automáticas (XSS, SQLi, SSRF com comprovação OOB).

> **Nota**: Alguns arquivos contêm código de exemplo que ainda requer pequenos ajustes (imports duplicados ou omissões). Utilize este guia como base para navegar e refatorar o projeto conforme suas necessidades.
