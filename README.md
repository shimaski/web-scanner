```
 _       ____________
| |     / / ____/ __ )
| | /| / / __/ / __  |
| |/ |/ / /___/ /_/ /
|__/|__/_____/_____/

   _____ _________    _   ___   ____________
  / ___// ____/   |  / | / / | / / ____/ __ \
  \__ \/ /   / /| | /  |/ /  |/ / __/ / /_/ /
 ___/ / /___/ ___ |/ /|  / /|  / /___/ _, _/
/____/\____/_/  |_/_/ |_/_/ |_/_____/_/ |_|
```

> Scanner de vulnerabilidades para aplicações web com interface CLI e web UI

Scanner de vulnerabilidades para aplicações web com interface CLI e web UI. Detecta vulnerabilidades em 20 categorias e gera relatórios em texto, JSON, HTML e PDF.

## Índice

- [Instalação](#instalação)
- [Quick Start](#quick-start)
- [CLI — Uso Completo](#cli--uso-completo)
  - [Target](#target)
  - [Módulos (20 scanners)](#módulos-20-scanners)
  - [Templates predefinidos](#templates-predefinidos)
  - [Opções de Scan](#opções-de-scan)
  - [Autenticação](#autenticação)
  - [Output e Formatos](#output-e-formatos)
  - [Crawl Mode](#crawl-mode)
  - [Plugin System](#plugin-system)
- [Web UI](#web-ui)
  - [Configuração de Scan](#configuração-de-scan)
  - [Resultados e Vulnerabilidades](#resultados-e-vulnerabilidades)
  - [Comparar Scans](#comparar-scans)
  - [Agendamento Recorrente](#agendamento-recorrente)
  - [Import Batch](#import-batch)
  - [Webhooks](#webhooks)
  - [Dashboard](#dashboard)
  - [API Endpoints](#api-endpoints)
- [Arquitetura do Projeto](#arquitetura-do-projeto)
- [Testes](#testes)

---

## Instalação

```bash
pip install .
```

Mode de desenvolvimento (instala como editable + dev deps):
```bash
pip install -e .
pip install -e ".[dev]"  # inclui ruff e mypy
```

### Dependências

- Python >= 3.10
- `requests`, `beautifulsoup4`, `urllib3`, `jinja2`, `flask`
- `fpdf` (geração de PDF, opcional)
- `bs4` (BeautifulSoup — já incluso nas deps acima)

---

## Quick Start

### CLI — comando mais simples
```bash
python -m web_scanner.main -t example.com
```
Rodada rápida de informação (header security, server detection).

### CLI — scan completo com relatório HTML
```bash
python -m web_scanner.main -t https://example.com --template full -f html -o report.html
```

### Web UI
```bash
python -m web_scanner.web_app
```
Abre em **http://localhost:5000**. Interface completa com painéis, agendamento, exportação e webhooks.

---

## CLI — Uso Completo

```
python -m web_scanner.main -t TARGET [opções]
```

### Target

| Flag | Descrição | Exemplo |
|------|-------------------|---------|
| `-t`, `--target` | URL ou hostname do alvo | `example.com`, `https://api.target.com:8080` |

O target pode ser um nome de domínio simples (prefixo `https://` automático), URL completa (`http://...` ou `https://...`), ou incluir porta (`http://localhost:3000`).

### Módulos (20 scanners)

Execute scanners específicos com `-m`:

```bash
# Scanner único
python -m web_scanner.main -t example.com -m xss

# Múltiplos scanners
python -m web_scanner.main -t example.com -m xss sqli redirect

# Todos os scanners
python -m web_scanner.main -t example.com -m all
```

| Módulo | Descrição | Técnicas |
|-----------|-------------------|-------------|
| `info` | Coleta de informações — security headers (CSP, HSTS, X-Frame-Options...), server fingerprinting (Nginx, Apache, Cloudflare...), tecnologia, arquivos sensíveis (robots.txt, .git, etc) | Passive reconnaissance |
| `xss` | XSS refletido — injeta payloads em parámetros de URL e verifica reflexão não-escapada no HTML da resposta | Reflected XSS, payload reflection check, HTML encoding bypass |
| `xss_stored` | XSS armazenado — submete payloads via formulários POST e verifica persistência em outras páginas | Stored/persistent XSS, mass exploitation via comments/profiles |
| `sqli` | SQL injection — error-based (padrões de erro de MySQL, PostgreSQL, MSSQL, Oracle, SQLite), boolean-based (mudança no tamanho da resposta), time-based (`SLEEP()`, `WAITFOR DELAY`) | Error injection, blind boolean, blind time-based |
| `traversal` | Path traversal & file inclusion — Linux (`/etc/passwd`), Windows (`windows\win.ini`), null bytes (`%00`), duplo encoding, UTF-8 bypass, overlong sequences | LFI/RFI, null byte injection, double/triple URL encoding, Unicode bypass |
| `redirect` | Open redirect — testa 3xx redirects, meta refresh, JavaScript sinks (`location.href`, `window.location`), parameter pollution (`url=good&url=evil`) | OAuth token theft, phishing chain, SSRF chaining |
| `csrf` | Verifica proteção CSRF em formulários (token names comuns) e cookies (atributo `SameSite`, `Secure`) | Missing CSRF token, SameSite bypass, cookie attribute analysis |
| `cors` | Misconfigurações CORS — wildcard (`*`), origin refletido, credenciais + wildcard, subdomínio permissivo | `Access-Control-Allow-Origin` abuse, reflected origin, subdomain wildcard |
| `ssrf` | Server-Side Request Forgery — cloud metadata (AWS 169.254.169.254), DNS rebinding (nip.io, sslip.io), redirect bypass, URL encoding bypass (octal, hex, decimal IP), internal network scan | Cloud credential theft, internal service access, DNS rebinding, bypass payloads |
| `crlf` | CRLF injection & HTTP response splitting — Unicode bypass (`%E5%98%8A%E5%98%8D`), duplo encoding, response splitting para criar segunda resposta HTTP | Set-Cookie injection, content injection, cache poisoning, response splitting |
| `dirb` | Diretorio brute force — concorrente (20 threads), filtragem de falsos positivos via 404 baseline, paths sensíveis (.env, .git, wp-admin, swagger, etc) | Favicon analysis, 404 baseline filtering, sensitive path detection |
| `fuzz` | Parameter Fuzzer — ffuf-style, auto-calibração, fuzzing de parâmetros com payloads de SQLi, XSS, CMDi, LFI, SSRF | Auto-calibration, baseline filtering, multi-vuln payload injection |
| `port` | Port scan — 26 portas comuns com sondagem concorrente (50 threads), HTTP banner grab (Server header, page title), detecção de portas de banco de dados expostas | TCP connect scan, HTTP banner grab, database port flagging |
| `ssl` | SSL/TLS — verificacão de certificado (emissor, self-signed, expiração), suporte a protocolo, cifras fracas | Certificate analysis, protocol version check, weak cipher detection |
| `subdomains` | Enumeração de subdomínio — DNS brute force concorrente (50 workers), probing HTTP nos descobertos (banner, title) | DNS resolution, HTTP scheme probing, service fingerprinting |
| `cmdi` | Command injection — time-based (`sleep`, `ping`), output-based (`whoami`, `id`, `/etc/passwd`), múltiplos separadores (`;`, `|`, `&&`, backticks, `$()`) | OS command injection, time-based detection, output-based detection |
| `xxe` | XML External Entity — file read (`/etc/passwd`, `win.ini`), SSRF via XXE, metadata exfiltration, entity detection | Out-of-band XXE, local file inclusion via DTD, internal network scan |
| `upload` | File upload — verifica formulários de upload (falta de `accept`, sem limite de tamanho, sem CSRF), tenta upload de arquivo PHP executável | Accept attribute check, size limit check, executable upload test |
| `http_verb` | HTTP verb tampering — testa métodos não-padrão (DELETE, PUT, PATCH, OPTIONS, TRACE, TRACK) em paths restritos, bypass de auth via verbo | Access control bypass, TRACE/TRACK (XST), method restriction check |
| `backup` | Arquivos expostos — backup/.git/.env/SQL dumps/configs/logs/Swagger/openapi, severity baseada na sensibilidade do arquivo | `.git/HEAD`, `.env`, `wp-config.php.bak`, SQL dumps, Swagger docs, lock files |

### Templates predefinidos

Conjuntos pre-configurados para cenários comuns:

| Template | Módulos | Quando usar | Duração estimada |
|----------|---------------------|-------------|------------------------|
| `quick` | `info`, `port`, `ssl` | Checagem rápida de infraestrutura | ~30 segundos |
| `fast` | `info`, `xss`, `redirect`, `cors` | Spot-check de segurança web app | ~1 minuto |
| `full` | Todos os 20 módulos | Assessment completo de vulnerabilidade | ~3-5 minutos |

```bash
python -m web_scanner.main -t example.com --template quick
python -m web_scanner.main -t example.com --template full
```

### Opções de Scan

| Flag | Padrão | Descrição |
|------|-----------|-------------------|
| `--crawl` | off | Executa spider web antes do scan para descobrir URLs, formulários e parámetros |
| `--threads` | `10` | Número máximo de threads concorrentes |
| `--timeout` | `10` | Timeout HTTP em segundos por requisição |
| `--delay` | `0.0` | Delay entre requisições (segundos) — útil para targets com rate limiting |
| `--proxy` | — | URL de proxy HTTP (ex: `http://127.0.0.1:8080` para Burp Suite ou OWASP ZAP) |
| `--ua` | `WebScanner/0.1.0` | Custom User-Agent |
| `--cookie` | — | Cookie string para scans autenticados (ex: `session=abc123; csrf_token=xyz`) |
| `--wordlist` | `wordlists/extended.txt` | Path custom para wordlist de diretório bruteforce |
| `-v`, `--verbose` | off | Log detalhado para debugging |

### Autenticação

Três métodos suportados, podendo ser combinados:

**HTTP Basic Auth:**
```bash
python -m web_scanner.main -t example.com \
  --basic-user admin --basic-pass secret123
```

**Bearer Token:**
```bash
python -m web_scanner.main -t example.com \
  --bearer "eyJhbGciOiJIUzI1NiIs..."
```

**Form Login (POST):**
```bash
python -m web_scanner.main -t example.com \
  --login-url /api/login \
  --login-user admin \
  --login-pass password123 \
  --login-user-field email \
  --login-pass-field password \
  --auto-relogin
```

O `--auto-relogin` faz re-login automático quando respostas 401/403 são detectadas durante o scan — útil para sessões que expiram.

### Output e Formatos

| Flag | Descrição |
|------|-------------------|
| `-f`, `--format` | Formato: `text` (console, padrão), `json`, `html` |
| `-o`, `--output` | Path do arquivo de saída |

```bash
# Saída no console (texto colorido)
python -m web_scanner.main -t example.com

# JSON (estrutura completa com findings)
python -m web_scanner.main -t example.com -m xss sqli -f json -o report.json

# HTML (relatório visual com cards por vulnerabilidade)
python -m web_scanner.main -t example.com --template full -f html -o report.html
```

Relatórios são ordenados por severidade: **CRITICAL > HIGH > MEDIUM > LOW > INFO**.

Via **Web UI**, exportação também suporta **PDF** (com fpdf).

### Crawl Mode

O `--crawl` roda um spider antes dos scanners:

```bash
python -m web_scanner.main -t example.com --crawl -m all
```

O crawler:
- Descobre links nos atributos `href`, `src`, `action`, `data-url`
- Extrai nomes de campos de formulários para targeting de parámetros
- Permanece no mesmo domínio (validação de netloc)
- Limite de 50 páginas (configurável no código)
- URLs e forms descobertos são passados a cada scanner para testes mais profundos

### Plugin System

Scanners customizados podem ser carregados de arquivos `.py` externos. Salve na pasta `web_scanner/plugins/` ou carregue de um diretório customizado:

```bash
python -m web_scanner.main -t example.com -m my_custom_scanner --plugin-dir ./my_plugins/
```

Exemplo de plugin:
```python
from web_scanner.scanner import BaseScanner

class MyScanner(BaseScanner):
    """Check for sensitive data in responses."""

    def run(self) -> list[dict]:
        findings = []
        resp = self.client.get("/")
        if resp is None:
            return findings
        if "password" in resp.text.lower() and "api_key" in resp.text.lower():
            findings.append({
                "severity": "HIGH",
                "title": "Hardcoded credentials detected",
                "detail": "Response contains both 'password' and 'api_key' strings",
            })
        return findings
```

---

## Web UI

```bash
python -m web_scanner.web_app
```

Abre em **http://localhost:5000** com interface moderna (tema escuro por padrão, alternável para claro), responsiva, com settings persistidos no `localStorage`.

### Configuração de Scan

Painel lateral (*Configuracao*) com:

- **Alvo** — campo de texto para URL
- **Templates** — chips selecionáveis: Quick, Fast, Full Audit
- **Scanners** — checkboxes individuais dos 20 módulos com descrição
- **Parámetros** — timeout, threads, delay, user-agent
- **Opções Avançadas** (colapsáveis):
  - Proxy (Burp/ZAP)
  - Cookie de autenticação
  - Basic Auth (usuario + senha)
  - Bearer Token
  - Form Login (URL, usuario, senha, field names)
  - Auto re-login
  - Crawling automático

### Resultados e Vulnerabilidades

- **Progress bar em tempo real** — mostra módulo atual e progresso do scan
- **Severity summary** — badges coloridos com contagem por nível + barra horizontal
- **Lista de findings** — cards numerados com badge de severidade, título e descrição detalhada
- **Possíveis Ataques** — seção colapsável em cada finding com:
  - Impact assessment
  - Attack scenarios (lista detalhada)
  - Chaining opportunities (como combinar com outros findings)
  - Real-world context (exemplos de incidentes reais)
  - Severity note
- **Export bar** — Download JSON, HTML, PDF + visualização inline de HTML/PDF em modal com iframe
- **Histórico de Scans** — lista na sidebar com status (executando/completado/erro), target e contagem

### Comparar Scans

Painel *Comparar* seleciona dois scans completados do mesmo target:
- Mostra stats de cada scan (target, total findings, data)
- **Delta** — diferença líquida de findings entre os scans
- **Novos no Scan B** — findings que apareceram na segunda execução (regressões)
- **Resolvidos (só no A)** — findings que foram corrigidos entre os scans

Uso ideal: executar scan antes e depois de deploy de fix para verificar correções.

### Agendamento Recorrente

Painel *Agendamento* cria scans periódicos:
- Criação: target, intervalo (horas), módulos
- **Pause/Resume** — pausar e retomar agendamentos
- **Run Now** — executar scan imediatamente sem resetar o timer
- **Edit Interval** — alterar frequência do agendamento
- Delete com confirmação
- Status visual: badge verde (Active) ou amarelo (Paused), última execução, próxima execução, contagem de runs

Persistência em SQLite — agendamentos sobrevivem a restarts do servidor.

### Import Batch

Painel *Importar* escaneia múltiplos targets de uma vez:
- Cola uma lista de targets (um por linha)
- Seleciona scanners
- Executa scans em paralelo (threads separadas por target)
- Os scans aparecem no histórico individualmente

```
example.com
https://sub1.example.com
api.example.com:8080
```

### Webhooks

Painel *Webhooks* configura notificações externas:
- Adiciona URLs de webhook (Slack, Discord, custom endpoints)
- Recebe payload JSON ao completar scans agendados com:
  - `event`: tipo do evento
  - `scan_id`, `target`, `total_findings`
  - `critical`, `high` (contagem)
  - `critical_findings` (top 5 findings CRITICAL)

### Dashboard

Painel *Dashboard* com estatísticas agregadas:
- **Total Scans** — todos os scans já executados
- **Completos** — scans finalizados com sucesso
- **Total Findings** — soma de todas as vulnerabilidades encontradas
- **Unique Targets** — quantos hosts diferentes foram escaneados
- **Gráfico de barras** por severidade (CRITICAL, HIGH, MEDIUM, LOW, INFO)

### API Endpoints

Todos os endpoints podem ser consumidos via REST:

| Method | Path | Descrição |
|--------|------|-------------------|
| `POST` | `/api/scan` | Iniciar scan (body: target, modules, auth, crawl, proxy, delay...) |
| `GET` | `/api/scan/<id>` | Status e resultados de um scan (inclui findings e by_severity) |
| `GET` | `/api/scans` | Lista todos os scans com status e totais |
| `DELETE` | `/api/delete/<id>` | Deletar scan e seus findings |
| `POST` | `/api/export/<id>` | Exportar relatório (body: `{"format":"pdf"}` — suporta json, html, pdf) |
| `GET` | `/api/view/<id>/<fmt>` | Visualizar relatório inline no browser |
| `GET` | `/api/compare/<a>/<b>` | Comparar dois scans (delta, novos, resolvidos) |
| `POST` | `/api/schedule` | Criar agendamento |
| `GET` | `/api/schedules` | Listar agendamentos |
| `DELETE` | `/api/schedule/<id>` | Deletar agendamento |
| `POST` | `/api/schedule/<id>/pause` | Pausar agendamento |
| `POST` | `/api/schedule/<id>/resume` | Retomar agendamento |
| `POST` | `/api/schedule/<id>/run-now` | Executar agendamento imediatamente |
| `PUT` | `/api/schedule/<id>/interval` | Alterar intervalo (horas) |
| `GET` | `/api/stats` | Estatísticas agregadas (total scans, findings, targets, por severidade) |
| `POST` | `/api/import` | Scan batch de múltiplos targets |
| `GET` | `/api/webhooks` | Listar webhooks |
| `POST` | `/api/webhooks` | Adicionar webhook |
| `DELETE` | `/api/webhooks` | Remover webhook |

---

## Arquitetura do Projeto

```
web_scanner/
  __main__.py            # Entry point (python -m web_scanner)
  main.py                # CLI — argparser, executação sequencial/paralela, output
  web_app.py             # Flask web UI — rotas API, scan em background, scheduler integration
  config.py              # ScanConfig — dataclass com todas as opções, factory from_dict()
  http_client.py         # HTTPClient — session com auth, proxy, cookies, auto-relogin
  scanner.py             # BaseScanner — classe abstrata para todos os scanners
  modules.py             # Registro central — SCANNER_MAP, MODULE_LABELS, TEMPLATES (20 scanners + plugins)
  utils.py               # Utilitários compartilhados — extract_params, extract_title, sort_findings, count_by_severity
  crawler.py             # Web spider — discovery de URLs, forms, parámetros
  database.py            # SQLite — scans, findings, scan_urls, schedules (thread-safe)
  report.py              # Geração de relatórios — console, JSON, HTML
  pdf_report.py          # Geração de PDF com fpdf
  attack_descriptions.py # Descrições detalhadas de vulnerabilidade — impact, cenários, chain, contexto real
  plugin_loader.py       # Carregamento dinámico de scanners de diretórios externos
  scheduler_service.py   # Agendamento recorrente — threading.Timer + SQLite persistence
  notifications.py       # Webhooks — envio de notificações de scan
  attack_descriptions.py # Vulnerability descriptions — impact, scenarios, chaining, real-world context
  modules:
    # — Injeção & Execução —
    sqli_scanner.py      # SQL injection (Error, Boolean, Time-based)
    xss_scanner.py       # XSS refletido (reflection check, encoding bypass)
    xss_stored.py        # XSS armazenado (POST submission, persistence check)
    cmd_injection.py     # Command injection (time-based, output-based)
    xxe_scanner.py       # XML External Entity (file read, SSRF via XXE)
    ssrf_scanner.py      # SSRF (metadata, DNS rebinding, redirect, bypass)
    crlf_scanner.py      # CRLF injection (Unicode bypass, response splitting)
    param_fuzzer.py      # Parameter fuzzer (ffuf-style, auto-calibration, multi-vuln)

    # — Autenticação & Sessão —
    csrf_scanner.py      # CSRF (missing token, SameSite, cookie attributes)
    cors_scanner.py      # CORS (wildcard, origin reflection, credentials, subdomain)

    # — Redirecionamento & Navegação —
    open_redirect.py     # Open redirect (3xx, meta refresh, JS sinks, pollution)
    path_traversal.py    # Path traversal (Linux, Windows, null bytes, encoding bypass)

    # — Infraestrutura —
    port_scan.py         # Port scan (TCP connect, HTTP banner, database flag)
    ssl_check.py         # SSL/TLS (certificate, protocol, weak cipher)
    subdomain_enum.py    # Subdomain enumeration (DNS brute force, HTTP probe)
    info_gather.py       # Information gathering (headers, server, technology)

    # — Files & Upload —
    dir_bruteforce.py    # Directory bruteforce (concurrent, 404 baseline, sensitive paths)
    upload_scanner.py    # File upload (accept attribute, size limits, CSRF, exec test)
    backup_scanner.py    # Backup files (.git, .env, SQL dumps, configs, logs)
    http_verb_scanner.py # HTTP verb tampering (TRACE, method bypass)
  templates/
    index.html           # Web UI frontend (dark/light theme, SPA, 6 tabs)
  wordlists/
    extended.txt         # Wordlist para directory bruteforce

tests/                   # 84 testes em 6 arquivos
pyproject.toml           # Configuração do projeto, scripts CLI, dependências
scans.db                 # SQLite database (auto-criado na primeira execução)
```

---

## Testes

```bash
python -m pytest tests/ -v
```

Testes cobrem:
- `test_config.py` — ScanConfig defaults e custom values
- `test_http_client.py` — URL normalization, URL joining, error handling, proxy, cookies
- `test_scanners.py` — InfoGatherer, CORSScanner, CSRFScanner, XSSScanner
- `test_new_scanners.py` — CommandInjection, XXEScanner, UploadScanner, HTTPVerb, BackupScanner
- `test_report.py` — JSON export, HTML export, console output
- `test_attack_descriptions.py` — Descrições por vulnerabilidade, fallback, structure validation
