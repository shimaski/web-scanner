# Changelog

Todas as mudanças notáveis neste projeto.

## [Unreleased]

### Bug Fixes
- **PDF via CLI** — adicionei `"pdf"` nas choices do `--format` e handler que chama `generate_pdf`. Antes o CLI ignorava pedidos de PDF.
- **Webhooks em scans manuais** — scans iniciados pela Web UI agora disparam `notify_scan_completed` para webhooks configurados. Antes só funcionava para agendamentos.
- **`fuzz` ausente do template Full no frontend** — o template `full` no `index.html` não incluía `fuzz`, o Parameter Fuzzer ficava de fora ao clicar "Full Audit".
- **`fpdf` ausente das dependências** — adicionei `fpdf>=1.7.2` ao `pyproject.toml`. Sem isso, `pip install .` instalava sem o fpdf e PDF quebrava com `ModuleNotFoundError`.

### Docs
- **README** — atualizado de 19 para 20 scanners, adicionada entrada do módulo `fuzz` na tabela e na seção de arquitetura.
- **CLI help** — epílogo atualizado com `fuzz` e indicação de 20 módulos no template full.
- **Frontend header** — `index.html` atualizado de "19 scanners" para "20 scanners".
