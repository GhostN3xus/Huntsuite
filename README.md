# HuntSuite

HuntSuite é um scaffold para uma plataforma de pentesting que combina descoberta, proxy, validação OOB e geração de relatórios.
Este pacote contém um esqueleto funcional com ferramentas básicas que você pode estender.

## Melhorias prioritárias — agora

1. Integrar Interactsh client (Go) e confirmar callbacks automaticamente
2. Melhorar enumeração de subdomínios (amass/subfinder/dnsx integration)
3. Implementar JS-aware mapper (chromedp) para SPAs
4. Transformar proxy num MITM com geração automática de CA para intercept HTTPS
5. Adicionar Intruder-like fuzzer integrado ao proxy com modos sniper/clusterbomb
6. Adicionar validações automáticas (SSRF/XSS/SQLi) com provas (OOB, timing, diffs)
7. Persistência robusta (SQLite) e UI para revisar findings
8. Fingerprinting avançado e correlação com CVEs
9. Adicionar testes unitários e pipeline CI
10. Melhorar UX do CLI (subcommands, profiles, YAML configs) e criar Web UI opcional

## Build
```
make build
./huntsuite --help
```

## Commands
- `proxy` — inicia um proxy forward básico
- `oob` — tenta usar cliente interactsh (externo) ou stub
- `recon` — enumeração básica de subdomínios (wordlist + external tools)
- `map` — crawler depth-limited
- `scan` — orquestrador simples
- `validate` — validações seguras SSRF (OOB) e grava findings

## Notes
- Este é um scaffold de desenvolvimento: integre ferramentas reais para produção.
