# Web Scanner

Scanner de vulnerabilidades para aplica&#231;&#245;es web com interface CLI e web UI. Detecta vulnerabilidades em 19 categorias e gera relat&#243;rios em texto, JSON, HTML e PDF.

## &#205;ndice

- [Instala&#231;&#227;o](#instala&#231;&#227;o)
- [Quick Start](#quick-start)
- [CLI — Uso Completo](#cli--uso-completo)
  - [Target](#target)
  - [M&#243;dulos (19 scanners)](#m&#243;dulos-19-scanners)
  - [Templates predefinidos](#templates-predefinidos)
  - [Op&#231;&#245;es de Scan](#op&#231;&#245;es-de-scan)
  - [Autentica&#231;&#227;o](#autentica&#231;&#227;o)
  - [Output e Formatos](#output-e-formatos)
  - [Crawl Mode](#crawl-mode)
  - [Plugin System](#plugin-system)
- [Web UI](#web-ui)
  - [Configura&#231;&#227;o de Scan](#configura&#231;&#227;o-de-scan)
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

## Instala&#231;&#227;o

```bash
pip install .
```

Mode de desenvolvimento (instala como editable + dev deps):
```bash
pip install -e .
pip install -e ".[dev]"  # inclui ruff e mypy
```

### Depend&#234;ncias

- Python >= 3.10
- `requests`, `beautifulsoup4`, `urllib3`, `jinja2`, `flask`
- `fpdf` (gera&#231;&#227;o de PDF, opcional)
- `bs4` (BeautifulSoup — j&#225; incluso nas deps acima)

---

## Quick Start

### CLI — comando mais simples
```bash
python -m web_scanner.main -t example.com
```
Rodada r&#225;pida de informa&#231;&#227;o (header security, server detection).

### CLI — scan completo com relat&#243;rio HTML
```bash
python -m web_scanner.main -t https://example.com --template full -f html -o report.html
```

### Web UI
```bash
python -m web_scanner.web_app
```
Abre em **http://localhost:5000**. Interface completa com pain&#233;is, agendamento, exporta&#231;&#227;o e webhooks.

---

## CLI — Uso Completo

```
python -m web_scanner.main -t TARGET [op&#231;&#245;es]
```

### Target

| Flag | Descri&#231;&#227;o | Exemplo |
|------|-------------------|---------|
| `-t`, `--target` | URL ou hostname do alvo | `example.com`, `https://api.target.com:8080` |

O target pode ser um nome de dom&#237;nio simples (prefixo `https://` autom&#225;tico), URL completa (`http://...` ou `https://...`), ou incluir porta (`http://localhost:3000`).

### M&#243;dulos (19 scanners)

Execute scanners espec&#237;ficos com `-m`:

```bash
# Scanner &#250;nico
python -m web_scanner.main -t example.com -m xss

# M&#250;ltiplos scanners
python -m web_scanner.main -t example.com -m xss sqli redirect

# Todos os scanners
python -m web_scanner.main -t example.com -m all
```

| M&#243;dulo | Descri&#231;&#227;o | T&#233;cnicas |
|-----------|-------------------|-------------|
| `info` | Coleta de informa&#231;&#245;es — security headers (CSP, HSTS, X-Frame-Options...), server fingerprinting (Nginx, Apache, Cloudflare...), tecnologia, arquivos sens&#237;veis (robots.txt, .git, etc) | Passive reconnaissance |
| `xss` | XSS refletido — injeta payloads em par&#225;metros de URL e verifica reflex&#227;o n&#227;o-escapada no HTML da resposta | Reflected XSS, payload reflection check, HTML encoding bypass |
| `xss_stored` | XSS armazenado — submete payloads via formul&#225;rios POST e verifica persist&#234;ncia em outras p&#225;ginas | Stored/persistent XSS, mass exploitation via comments/profiles |
| `sqli` | SQL injection — error-based (padr&#245;es de erro de MySQL, PostgreSQL, MSSQL, Oracle, SQLite), boolean-based (mudan&#231;a no tamanho da resposta), time-based (`SLEEP()`, `WAITFOR DELAY`) | Error injection, blind boolean, blind time-based |
| `traversal` | Path traversal & file inclusion — Linux (`/etc/passwd`), Windows (`windows\win.ini`), null bytes (`%00`), duplo encoding, UTF-8 bypass, overlong sequences | LFI/RFI, null byte injection, double/triple URL encoding, Unicode bypass |
| `redirect` | Open redirect — testa 3xx redirects, meta refresh, JavaScript sinks (`location.href`, `window.location`), parameter pollution (`url=good&url=evil`) | OAuth token theft, phishing chain, SSRF chaining |
| `csrf` | Verifica prote&#231;&#227;o CSRF em formul&#225;rios (token names comuns) e cookies (atributo `SameSite`, `Secure`) | Missing CSRF token, SameSite bypass, cookie attribute analysis |
| `cors` | Misconfigura&#231;&#245;es CORS — wildcard (`*`), origin refletido, credenciais + wildcard, subdom&#237;nio permissivo | `Access-Control-Allow-Origin` abuse, reflected origin, subdomain wildcard |
| `ssrf` | Server-Side Request Forgery — cloud metadata (AWS 169.254.169.254), DNS rebinding (nip.io, sslip.io), redirect bypass, URL encoding bypass (octal, hex, decimal IP), internal network scan | Cloud credential theft, internal service access, DNS rebinding, bypass payloads |
| `crlf` | CRLF injection & HTTP response splitting — Unicode bypass (`%E5%98%8A%E5%98%8D`), duplo encoding, response splitting para criar segunda resposta HTTP | Set-Cookie injection, content injection, cache poisoning, response splitting |
| `dirb` | Diretorio brute force — concorrente (20 threads), filtragem de falsos positivos via 404 baseline, paths sens&#237;veis (.env, .git, wp-admin, swagger, etc) | Favicon analysis, 404 baseline filtering, sensitive path detection |
| `port` | Port scan — 26 portas comuns com sondagem concorrente (50 threads), HTTP banner grab (Server header, page title), detec&#231;&#227;o de portas de banco de dados expostas | TCP connect scan, HTTP banner grab, database port flagging |
| `ssl` | SSL/TLS — verificac&#227;o de certificado (emissor, self-signed, expira&#231;&#227;o), suporte a protocolo, cifras fracas | Certificate analysis, protocol version check, weak cipher detection |
| `subdomains` | Enumera&#231;&#227;o de subdom&#237;nio — DNS brute force concorrente (50 workers), probing HTTP nos descobertos (banner, title) | DNS resolution, HTTP scheme probing, service fingerprinting |
| `cmdi` | Command injection — time-based (`sleep`, `ping`), output-based (`whoami`, `id`, `/etc/passwd`), m&#250;ltiplos separadores (`;`, `|`, `&&`, backticks, `$()`) | OS command injection, time-based detection, output-based detection |
| `xxe` | XML External Entity — file read (`/etc/passwd`, `win.ini`), SSRF via XXE, metadata exfiltration, entity detection | Out-of-band XXE, local file inclusion via DTD, internal network scan |
| `upload` | File upload — verifica formul&#225;rios de upload (falta de `accept`, sem limite de tamanho, sem CSRF), tenta upload de arquivo PHP execut&#225;vel | Accept attribute check, size limit check, executable upload test |
| `http_verb` | HTTP verb tampering — testa m&#233;todos n&#227;o-padr&#227;o (DELETE, PUT, PATCH, OPTIONS, TRACE, TRACK) em paths restritos, bypass de auth via verbo | Access control bypass, TRACE/TRACK (XST), method restriction check |
| `backup` | Arquivos expostos — backup/.git/.env/SQL dumps/configs/logs/Swagger/openapi, severity baseada na sensibilidade do arquivo | `.git/HEAD`, `.env`, `wp-config.php.bak`, SQL dumps, Swagger docs, lock files |

### Templates predefinidos

Conjuntos pre-configurados para cen&#225;rios comuns:

| Template | M&#243;dulos | Quando usar | Dura&#231;&#227;o estimada |
|----------|---------------------|-------------|------------------------|
| `quick` | `info`, `port`, `ssl` | Checagem r&#225;pida de infraestrutura | ~30 segundos |
| `fast` | `info`, `xss`, `redirect`, `cors` | Spot-check de seguran&#231;a web app | ~1 minuto |
| `full` | Todos os 19 m&#243;dulos | Assessment completo de vulnerabilidade | ~3-5 minutos |

```bash
python -m web_scanner.main -t example.com --template quick
python -m web_scanner.main -t example.com --template full
```

### Op&#231;&#245;es de Scan

| Flag | Padr&#227;o | Descri&#231;&#227;o |
|------|-----------|-------------------|
| `--crawl` | off | Executa spider web antes do scan para descobrir URLs, formul&#225;rios e par&#225;metros |
| `--threads` | `10` | N&#250;mero m&#225;ximo de threads concorrentes |
| `--timeout` | `10` | Timeout HTTP em segundos por requisi&#231;&#227;o |
| `--delay` | `0.0` | Delay entre requisi&#231;&#245;es (segundos) — &#250;til para targets com rate limiting |
| `--proxy` | — | URL de proxy HTTP (ex: `http://127.0.0.1:8080` para Burp Suite ou OWASP ZAP) |
| `--ua` | `WebScanner/0.1.0` | Custom User-Agent |
| `--cookie` | — | Cookie string para scans autenticados (ex: `session=abc123; csrf_token=xyz`) |
| `--wordlist` | `wordlists/extended.txt` | Path custom para wordlist de diret&#243;rio bruteforce |
| `-v`, `--verbose` | off | Log detalhado para debugging |

### Autentica&#231;&#227;o

Tr&#234;s m&#233;todos suportados, podendo ser combinados:

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

O `--auto-relogin` faz re-login autom&#225;tico quando respostas 401/403 s&#227;o detectadas durante o scan — &#250;til para sess&#245;es que expiram.

### Output e Formatos

| Flag | Descri&#231;&#227;o |
|------|-------------------|
| `-f`, `--format` | Formato: `text` (console, padr&#227;o), `json`, `html` |
| `-o`, `--output` | Path do arquivo de sa&#237;da |

```bash
# Sa&#237;da no console (texto colorido)
python -m web_scanner.main -t example.com

# JSON (estrutura completa com findings)
python -m web_scanner.main -t example.com -m xss sqli -f json -o report.json

# HTML (relat&#243;rio visual com cards por vulnerabilidade)
python -m web_scanner.main -t example.com --template full -f html -o report.html
```

Relat&#243;rios s&#227;o ordenados por severidade: **CRITICAL > HIGH > MEDIUM > LOW > INFO**.

Via **Web UI**, exporta&#231;&#227;o tamb&#233;m suporta **PDF** (com fpdf).

### Crawl Mode

O `--crawl` roda um spider antes dos scanners:

```bash
python -m web_scanner.main -t example.com --crawl -m all
```

O crawler:
- Descobre links nos atributos `href`, `src`, `action`, `data-url`
- Extrai nomes de campos de formul&#225;rios para targeting de par&#225;metros
- Permanece no mesmo dom&#237;nio (valida&#231;&#227;o de netloc)
- Limite de 50 p&#225;ginas (configur&#225;vel no c&#243;digo)
- URLs e forms descobertos s&#227;o passados a cada scanner para testes mais profundos

### Plugin System

Scanners customizados podem ser carregados de arquivos `.py` externos. Salve na pasta `web_scanner/plugins/` ou carregue de um diret&#243;rio customizado:

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

Abre em **http://localhost:5000** com interface moderna (tema escuro por padr&#227;o, altern&#225;vel para claro), responsiva, com settings persistidos no `localStorage`.

### Configura&#231;&#227;o de Scan

Painel lateral (*Configuracao*) com:

- **Alvo** — campo de texto para URL
- **Templates** — chips selecion&#225;veis: Quick, Fast, Full Audit
- **Scanners** — checkboxes individuais dos 19 m&#243;dulos com descri&#231;&#227;o
- **Par&#225;metros** — timeout, threads, delay, user-agent
- **Op&#231;&#245;es Avan&#231;adas** (colaps&#225;veis):
  - Proxy (Burp/ZAP)
  - Cookie de autentica&#231;&#227;o
  - Basic Auth (usuario + senha)
  - Bearer Token
  - Form Login (URL, usuario, senha, field names)
  - Auto re-login
  - Crawling autom&#225;tico

### Resultados e Vulnerabilidades

- **Progress bar em tempo real** — mostra m&#243;dulo atual e progresso do scan
- **Severity summary** — badges coloridos com contagem por n&#237;vel + barra horizontal
- **Lista de findings** — cards numerados com badge de severidade, t&#237;tulo e descri&#231;&#227;o detalhada
- **Poss&#237;veis Ataques** — se&#231;&#227;o colaps&#225;vel em cada finding com:
  - Impact assessment
  - Attack scenarios (lista detalhada)
  - Chaining opportunities (como combinar com outros findings)
  - Real-world context (exemplos de incidentes reais)
  - Severity note
- **Export bar** — Download JSON, HTML, PDF + visualiza&#231;&#227;o inline de HTML/PDF em modal com iframe
- **Hist&#243;rico de Scans** — lista na sidebar com status (executando/completado/erro), target e contagem

### Comparar Scans

Painel *Comparar* seleciona dois scans completados do mesmo target:
- Mostra stats de cada scan (target, total findings, data)
- **Delta** — diferen&#231;a l&#237;quida de findings entre os scans
- **Novos no Scan B** — findings que apareceram na segunda execu&#231;&#227;o (regress&#245;es)
- **Resolvidos (s&#243; no A)** — findings que foram corrigidos entre os scans

Uso ideal: executar scan antes e depois de deploy de fix para verificar corre&#231;&#245;es.

### Agendamento Recorrente

Painel *Agendamento* cria scans peri&#243;dicos:
- Cria&#231;&#227;o: target, intervalo (horas), m&#243;dulos
- **Pause/Resume** — pausar e retomar agendamentos
- **Run Now** — executar scan imediatamente sem resetar o timer
- **Edit Interval** — alterar frequ&#234;ncia do agendamento
- Delete com confirma&#231;&#227;o
- Status visual: badge verde (Active) ou amarelo (Paused), &#250;ltima execu&#231;&#227;o, pr&#243;xima execu&#231;&#227;o, contagem de runs

Persist&#234;ncia em SQLite — agendamentos sobrevivem a restarts do servidor.

### Import Batch

Painel *Importar* escaneia m&#250;ltiplos targets de uma vez:
- Cola uma lista de targets (um por linha)
- Seleciona scanners
- Executa scans em paralelo (threads separadas por target)
- Os scans aparecem no hist&#243;rico individualmente

```
example.com
https://sub1.example.com
api.example.com:8080
```

### Webhooks

Painel *Webhooks* configura notifica&#231;&#245;es externas:
- Adiciona URLs de webhook (Slack, Discord, custom endpoints)
- Recebe payload JSON ao completar scans agendados com:
  - `event`: tipo do evento
  - `scan_id`, `target`, `total_findings`
  - `critical`, `high` (contagem)
  - `critical_findings` (top 5 findings CRITICAL)

### Dashboard

Painel *Dashboard* com estat&#237;sticas agregadas:
- **Total Scans** — todos os scans j&#225; executados
- **Completos** — scans finalizados com sucesso
- **Total Findings** — soma de todas as vulnerabilidades encontradas
- **Unique Targets** — quantos hosts diferentes foram escaneados
- **Gr&#225;fico de barras** por severidade (CRITICAL, HIGH, MEDIUM, LOW, INFO)

### API Endpoints

Todos os endpoints podem ser consumidos via REST:

| Method | Path | Descri&#231;&#227;o |
|--------|------|-------------------|
| `POST` | `/api/scan` | Iniciar scan (body: target, modules, auth, crawl, proxy, delay...) |
| `GET` | `/api/scan/<id>` | Status e resultados de um scan (inclui findings e by_severity) |
| `GET` | `/api/scans` | Lista todos os scans com status e totais |
| `DELETE` | `/api/delete/<id>` | Deletar scan e seus findings |
| `POST` | `/api/export/<id>` | Exportar relat&#243;rio (body: `{"format":"pdf"}` — suporta json, html, pdf) |
| `GET` | `/api/view/<id>/<fmt>` | Visualizar relat&#243;rio inline no browser |
| `GET` | `/api/compare/<a>/<b>` | Comparar dois scans (delta, novos, resolvidos) |
| `POST` | `/api/schedule` | Criar agendamento |
| `GET` | `/api/schedules` | Listar agendamentos |
| `DELETE` | `/api/schedule/<id>` | Deletar agendamento |
| `POST` | `/api/schedule/<id>/pause` | Pausar agendamento |
| `POST` | `/api/schedule/<id>/resume` | Retomar agendamento |
| `POST` | `/api/schedule/<id>/run-now` | Executar agendamento imediatamente |
| `PUT` | `/api/schedule/<id>/interval` | Alterar intervalo (horas) |
| `GET` | `/api/stats` | Estat&#237;sticas agregadas (total scans, findings, targets, por severidade) |
| `POST` | `/api/import` | Scan batch de m&#250;ltiplos targets |
| `GET` | `/api/webhooks` | Listar webhooks |
| `POST` | `/api/webhooks` | Adicionar webhook |
| `DELETE` | `/api/webhooks` | Remover webhook |

---

## Arquitetura do Projeto

```
web_scanner/
  __main__.py            # Entry point (python -m web_scanner)
  main.py                # CLI — argparser, executa&#231;&#227;o sequencial/paralela, output
  web_app.py             # Flask web UI — rotas API, scan em background, scheduler integration
  config.py              # ScanConfig — dataclass com todas as op&#231;&#245;es, factory from_dict()
  http_client.py         # HTTPClient — session com auth, proxy, cookies, auto-relogin
  scanner.py             # BaseScanner — classe abstrata para todos os scanners
  modules.py             # Registro central — SCANNER_MAP, MODULE_LABELS, TEMPLATES (19 scanners + plugins)
  utils.py               # Utilit&#225;rios compartilhados — extract_params, extract_title, sort_findings, count_by_severity
  crawler.py             # Web spider — discovery de URLs, forms, par&#225;metros
  database.py            # SQLite — scans, findings, scan_urls, schedules (thread-safe)
  report.py              # Gera&#231;&#227;o de relat&#243;rios — console, JSON, HTML
  pdf_report.py          # Gera&#231;&#227;o de PDF com fpdf
  attack_descriptions.py # Descri&#231;&#245;es detalhadas de vulnerabilidade — impact, cen&#225;rios, chain, contexto real
  plugin_loader.py       # Carregamento din&#225;mico de scanners de diret&#243;rios externos
  scheduler_service.py   # Agendamento recorrente — threading.Timer + SQLite persistence
  notifications.py       # Webhooks — envio de notifica&#231;&#245;es de scan
  attack_descriptions.py # Vulnerability descriptions — impact, scenarios, chaining, real-world context
  modules:
    # — Inje&#231;&#227;o & Execu&#231;&#227;o —
    sqli_scanner.py      # SQL injection (Error, Boolean, Time-based)
    xss_scanner.py       # XSS refletido (reflection check, encoding bypass)
    xss_stored.py        # XSS armazenado (POST submission, persistence check)
    cmd_injection.py     # Command injection (time-based, output-based)
    xxe_scanner.py       # XML External Entity (file read, SSRF via XXE)
    ssrf_scanner.py      # SSRF (metadata, DNS rebinding, redirect, bypass)
    crlf_scanner.py      # CRLF injection (Unicode bypass, response splitting)

    # — Autentica&#231;&#227;o & Sess&#227;o —
    csrf_scanner.py      # CSRF (missing token, SameSite, cookie attributes)
    cors_scanner.py      # CORS (wildcard, origin reflection, credentials, subdomain)

    # — Redirecionamento & Navega&#231;&#227;o —
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
pyproject.toml           # Configura&#231;&#227;o do projeto, scripts CLI, depend&#234;ncias
scans.db                 # SQLite database (auto-criado na primeira execu&#231;&#227;o)
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
- `test_attack_descriptions.py` — Descri&#231;&#245;es por vulnerabilidade, fallback, structure validation
