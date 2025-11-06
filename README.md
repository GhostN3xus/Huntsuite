# HuntSuite

```
██╗  ██╗██╗   ██╗███╗   ██╗████████ ███████  ╗██╗   ██╗██╗████████ ███████
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════  ║██    ██ ██║   ██║   ██╔
███████║██║   ██║██╔██╗ ██║   ██║   ███████╗  ██║   ██║██║   ██║   █████ 
██╔══██║██║   ██║██║╚██╗██║   ██║   ╚═══ ██║  ██║   ██║██║   ██║   ██╔ 
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████║  ╚██████  ██║   ██║   ███████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝  ╚═════╝ ╚══╝    ╚═╝ ╚════════╝ 
```

O HuntSuite é um mecanismo de automação ofensiva focado em reconhecimento e validação de alto sinal. Ele é projetado para ser uma ferramenta poderosa e extensível para caçadores de bugs e profissionais de segurança.

**Aviso Legal:** O uso desta ferramenta é apenas para fins educacionais e de pesquisa autorizados. Não a utilize em sistemas para os quais você não tem permissão explícita.

---

## Tabela de Conteúdos

- [Instalação](#instalação)
- [Uso](#uso)
  - [Comandos](#comandos)
  - [Sinalizadores Globais](#sinalizadores-globais)
  - [Exemplos](#exemplos)
- [Arquitetura](#arquitetura)
  - [Sistema de Módulos](#sistema-de-módulos)
- [Desenvolvimento](#desenvolvimento)
  - [Pré-requisitos](#pré-requisitos)
  - [Construindo o Binário](#construindo-o-binário)
  - [Executando Testes](#executando-testes)
- [Contribuição](#contribuição)

---

## Instalação

```bash
go install github.com/GhostN3xus/Huntsuite/cmd/huntsuite@latest
```

## Uso

### Comandos

| Comando    | Descrição                                                               |
|------------|-------------------------------------------------------------------------|
| `scan`     | Executa o mecanismo de varredura completo em um alvo.                   |
| `recon`    | Realiza a enumeração de subdomínios com base em uma lista de palavras.  |
| `validate` | Dispara uma sonda SSRF com suporte OOB em uma única URL de destino.     |
| `findings` | Lista os resultados de uma varredura específica.                        |
| `report`   | Gera relatórios para os resultados da varredura.                        |

### Sinalizadores Globais

| Sinalizador | Descrição                                  |
|-------------|--------------------------------------------|
| `--config`  | Caminho para o arquivo de configuração.      |
| `-q`, `--quiet` | Suprime os logs, exibindo apenas os erros.   |
| `-v`, `--verbose` | Ativa o log detalhado.                     |
| `--debug`   | Ativa o log de depuração.                    |

### Exemplos

**Executar uma varredura de XSS e SQLi em um alvo:**
```bash
huntsuite scan -u example.com -m xss,sqli -t 30 -o findings.json
```

**Realizar reconhecimento de subdomínio:**
```bash
huntsuite recon -d example.com -o subs.txt
```

**Validar um endpoint para SSRF:**
```bash
huntsuite validate -u https://sub.example.com --oob -p "param"
```

## Arquitetura

O HuntSuite é construído com uma arquitetura modular e extensível para facilitar a adição de novas funcionalidades.

*   **CLI:** Construída com o [Cobra](https://cobra.dev/), fornecendo uma interface de linha de comando robusta e extensível.
*   **Configuração:** Gerenciada por meio de um arquivo `config.yaml`, permitindo uma personalização detalhada.
*   **Armazenamento:** Os resultados são armazenados em um banco de dados SQLite, fornecendo um armazenamento persistente e consultável.

### Sistema de Módulos

O coração do HuntSuite é seu sistema de módulos, que permite a adição de novos geradores de payload, bypassers de WAF e validadores de vulnerabilidade.

*   **PayloadGenerator:** Gera payloads com base no contexto do alvo.
*   **WAFBypasser:** Aplica técnicas de bypass de WAF aos payloads.
*   **VulnerabilityValidator:** Valida vulnerabilidades analisando as respostas HTTP e as interações OOB.

## Desenvolvimento

### Pré-requisitos

*   Go 1.21+
*   Ambiente Linux x86_64

### Construindo o Binário

```bash
go build ./cmd/huntsuite
```

### Executando Testes

```bash
go test ./...
```

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir uma issue ou um pull request.
