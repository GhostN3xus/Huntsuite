```
██╗  ██╗██╗   ██╗███╗   ██╗████████ ███████  ╗██╗   ██╗██╗████████ ███████
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════  ║██    ██ ██║   ██║   ██╔
███████║██║   ██║██╔██╗ ██║   ██║   ███████╗  ██║   ██║██║   ██║   █████ 
██╔══██║██║   ██║██║╚██╗██║   ██║   ╚═══ ██║  ██║   ██║██║   ██║   ██╔ 
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████║  ╚██████  ██║   ██║   ███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝  ╚═════╝ ╚══╝    ╚═╝ ╚════════╝ 
```

O HuntSuite é um mecanismo de automação ofensiva focado em reconhecimento e validação de alto sinal. Ele executa reconhecimento de DNS, mapeamento estrutural, sondagem de divulgação de arquivos confidenciais e validação automática de OOB (SSRF, Blind XSS, Log4Shell).

## Instalação

```bash
go install github.com/GhostN3xus/Huntsuite@latest
```

## Comandos

| Comando    | Descrição                                                               |
|------------|-------------------------------------------------------------------------|
| `scan`     | Executa o mecanismo de varredura completo em um alvo.                   |
| `recon`    | Realiza a enumeração de subdomínios com base em uma lista de palavras.  |
| `validate` | Dispara uma sonda SSRF com suporte OOB em uma única URL de destino.     |
| `findings` | Lista os resultados de uma varredura específica.                        |
| `report`   | Gera relatórios para os resultados da varredura.                        |

### Exemplos

```bash
huntsuite scan -u example.com -m xss,sqli -t 30 -o findings.json
huntsuite recon -d example.com -o subs.txt
huntsuite validate -u https://sub.example.com --oob -p "param"
huntsuite findings --scan-id 1
huntsuite report --scan-id 1 --format html
```

### Sinalizadores Globais

* `--config` — Caminho para o arquivo de configuração.
* `-q`, `--quiet` — Suprime os logs, exibindo apenas os erros.
* `-v`, `--verbose` — Ativa o log detalhado.
* `--debug` — Ativa o log de depuração.

## Arquitetura

* **CLI:** Construída com o Cobra, fornecendo uma interface de linha de comando robusta e extensível.
* **Configuração:** Gerenciada por meio de um arquivo `config.yaml`, permitindo uma personalização detalhada.
* **Recon:** O `pkg/recon` realiza a enumeração de subdomínios usando uma lista de palavras incorporada e um resolvedor de DNS personalizado.
* **Scanner:** O `pkg/scanner` contém a lógica principal para a varredura de vulnerabilidades, com suporte para vários tipos de varredura.
* **Validação OOB:** O `pkg/validator` integra-se a um cliente Interactsh para confirmar as vulnerabilidades de OOB.
* **Armazenamento:** Os resultados são armazenados em um banco de dados SQLite, fornecendo um armazenamento persistente e consultável.

## Desenvolvimento

### Pré-requisitos

* Go 1.21+
* Ambiente Linux x86_64

### Executando Testes

```bash
go test ./...
```

### Construindo o Binário

```bash
go build ./cmd/huntsuite
```

---

Use o HuntSuite com responsabilidade. Os testes ofensivos devem ser direcionados apenas a ativos que você possui ou tem permissão explícita para avaliar.
