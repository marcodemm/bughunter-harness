# Bughunter Harness

![Bughunter Harness — a run that found a vulnerability](images/bughunter-harness-found-vuln.png)

Autonomous local-LLM pentest agent. Multi-agent orchestrated pipeline (recon → fingerprint → content discovery → **login probe (lab only)** → web vuln scan (+ sqlmap + dalfox on parameterized endpoints) → wordpress → api fuzzer → auth → report) driven by any OpenAI-compatible LLM (LM Studio, Ollama, Llama.cpp, or a cloud provider). Rate-limited, scope-gated, redacted-by-default. Attribution headers, email + Telegram notifications, temp-file cleanup, and a live progress panel.

**Design goals** — safe by default (rate limit, scope allowlist, redact secrets, no destructive commands), model-agnostic, plug-and-play with the arsenal you already have on your machine.

Read `harness.py --help` for the full flag reference.

---

## Requirements

### 1. Python

- **Python 3.10+** (uses `str | None` syntax and `type | X` unions).
- `pip` / `venv` (bundled with Python).

### 2. Docker (optional, for lab targets)

- **Docker Desktop** (macOS/Windows) or `docker` CLI (Linux). Only needed if you want to spin up local vulnerable apps (DVWA, Juice Shop, VulHub, …) to test the pipeline.

### 3. LLM backend (pick one)

The harness auto-probes local backends in this order. Also accepts cloud providers with explicit `--servertype`.

| Backend | Install | Default endpoint |
|---|---|---|
| **LM Studio** | https://lmstudio.ai (GUI + local server) | `http://127.0.0.1:1234/v1` |
| **Ollama** | `brew install ollama` (macOS) / official installer | `http://127.0.0.1:11434/v1` |
| **Llama.cpp** | `brew install llama.cpp` (macOS) then `llama-server -m model.gguf --port 8080` | `http://127.0.0.1:8080/v1` |
| **OpenAI** | `export OPENAI_API_KEY=sk-...` | `https://api.openai.com/v1` |
| **Anthropic** | `export ANTHROPIC_API_KEY=sk-ant-...` | `https://api.anthropic.com/v1` |
| **NVIDIA NIM** | `export NVIDIA_API_KEY=nvapi-...` (build.nvidia.com) | `https://integrate.api.nvidia.com/v1` |
| **Google Gemini** | `export GEMINI_API_KEY=AIza...` (ai.google.dev) | `https://generativelanguage.googleapis.com/v1beta/openai` |

**Recommended for privacy + zero cost**: run any 7B–35B model locally in LM Studio or Ollama. Cloud backends work fine but you pay per token and traffic leaves your machine.

**⭐ Recommended model for this harness — `Qwen3.5-35B-A3B-uncensored-bughunter-v8`**
([mmp2055/Qwen3.5-35B-A3B-uncensored-bughunter-v8 on Hugging Face](https://huggingface.co/mmp2055/Qwen3.5-35B-A3B-uncensored-bughunter-v8)).
A Qwen 3.5 35B MoE (3B active params) fine-tuned specifically for bug-bounty /
offensive-security workflows: prefers concrete tool calls over hand-wavy prose,
knows nuclei / ffuf / sqlmap / dalfox / gau / katana / dnsx flags without
hand-holding, and doesn't refuse lab-only default-cred probes on DVWA / Juice
Shop / Mutillidae. Runs comfortably on a single Mac (Apple Silicon,
≥ 32 GB RAM) via LM Studio. The default `llm.model` in
[`config.example.yaml`](config.example.yaml) is pinned to this model — change
it if you prefer a different backend.

Setup with LM Studio (fastest path):

1. Install LM Studio → https://lmstudio.ai
2. Search & download **`mmp2055/Qwen3.5-35B-A3B-uncensored-bughunter-v8`** (~19 GB Q4_K_M).
3. In LM Studio → *Developer* → *Local Server* → **Start Server** on port 1234.
4. Turn **OFF Speculative Decoding** in the model's *Settings* (Qwen 3.5 MoE
   fails to load with MTP on).
5. Enable **Tool Use** in the model's *Settings* (required for the agent
   pipeline).

### 4. Offensive tools (nuclei / ffuf / etc.)

The agents run these binaries via `run_shell`. Install what you plan to use — nothing is required, but with more tools installed the harness discovers more.

**One-liner install (macOS Homebrew, most useful subset):**
```bash
brew install nuclei ffuf httpx subfinder katana nmap nikto \
             feroxbuster wpscan dnsx naabu jq \
             sqlmap
# Optional: gau, waybackurls, whois, dig (dig ships with macOS)
brew install gau waybackurls
# Active XSS scanner (dalfox is only on go)
go install github.com/hahwul/dalfox/v2@latest
```

**On Linux (apt)** most of these come from the ProjectDiscovery `go install` route:
```bash
# ProjectDiscovery bundle
for tool in nuclei ffuf httpx subfinder katana dnsx naabu; do
  go install -v github.com/projectdiscovery/$tool/v3/cmd/$tool@latest
done
sudo apt install nmap nikto wpscan jq sqlmap
# Active XSS scanner
go install github.com/hahwul/dalfox/v2@latest
```

**Update nuclei templates** on first run (or periodically):
```bash
nuclei -update-templates
```

**Why `sqlmap` + `dalfox` matter**: nuclei/nikto are CVE-oriented (they catch known-vulnerable versions and misconfigurations). Real modern apps ship without exploitable CVEs but leak SQLi/XSS through their own custom code. The `web_vuln` agent runs `dalfox url` + `sqlmap --batch --smart --level=1 --risk=1` against every endpoint the `content_discovery` agent found with GET parameters — that is the difference between "0 findings" and "the SQLi/XSS this app actually has".

### 5. Wordlists — SecLists

Several agents (content discovery, api fuzzer) invoke `ffuf` with a wordlist from **SecLists** at the default path `/opt/homebrew/share/seclists/…`. Install once:

```bash
# macOS / Linux (git clone, ~1.5 GB uncompressed)
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
     /opt/homebrew/share/seclists

# Or tarball if git is slow (~250 MB compressed)
curl -sL https://github.com/danielmiessler/SecLists/archive/refs/heads/master.tar.gz \
     -o /tmp/seclists.tar.gz
sudo mkdir -p /opt/homebrew/share && cd /opt/homebrew/share
sudo tar -xzf /tmp/seclists.tar.gz && sudo mv SecLists-master seclists
sudo rm /tmp/seclists.tar.gz
```

If your system uses a different path (e.g. `/usr/share/seclists/`), the agents fall back to `ls`-and-probe common locations. Adjust prompt in `agents/content_discovery.py` if none fit.

### 6. (Optional) `mailpit` for local email testing

If you want to receive the end-of-pipeline email but don't want to configure a real SMTP relay, install [Mailpit](https://mailpit.axllent.org/):
```bash
brew install mailpit && mailpit
# Web UI: http://localhost:8025
# SMTP:   127.0.0.1:1025
```
Then in `config.yaml`:
```yaml
smtp:
  host: "127.0.0.1"
  port: 1025
  from: "harness@localhost"
  username: ""
  default_to: "you@localhost"
```

### 7. (Optional) Telegram bot

For end-of-pipeline Telegram notifications:
1. In Telegram, talk to `@BotFather` → `/newbot` → save the token.
2. Start a chat with your new bot (send any message).
3. Get your `chat_id`:
   ```bash
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | jq '.result[0].message.chat.id'
   ```
4. Either export the token as an env var:
   ```bash
   export TELEGRAM_BOT_TOKEN='123456:ABC-DEF...'
   ```
   Or paste it directly in `config.yaml → telegram.bot_token`.
5. Enable in `config.yaml`:
   ```yaml
   telegram:
     enabled: true
     chat_id: "your-chat-id-here"
   ```

---

## Setup (one time)

```bash
git clone https://github.com/<your-fork>/bughunter-harness.git
cd bughunter-harness
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Copy templates
cp config.example.yaml config.yaml
cp scope.example.txt scope.txt

# Edit config.yaml (backend, SMTP/Telegram optional, custom_headers, …)
# Edit scope.txt with the hostnames you are authorized to test
```

---

## Quick start

```bash
source .venv/bin/activate
python harness.py
```

At the prompt:
```
Objective (one-line goal for the agent). Type /quit or /bye to exit.
Inline flags (sticky): --email ADDR  --scope PAT (repeat)  -o PATH

> http://localhost:3000/
```

The orchestrator will run the 9 agents in sequence and produce a `sessions/<run-id>/REPORT.md` at the end.

**Pipeline (order matters — cookies from step 4 feed into step 5):**
1. `recon` — subdomain + host + port enumeration
2. `fingerprint` — tech-stack detection
3. `content_discovery` — hidden paths + historical URLs (adds `-H "Cookie: …"` if step 4 already captured one; usually it hasn't yet on first pass)
4. `login_probe` — **LAB ONLY** (localhost / private IP / DVWA / Juice Shop / Mutillidae / bWAPP / WebGoat) — tries 6 stock default-cred pairs (`admin:password`, `admin:admin`, …), harvests the session cookie into `state.session_cookies`
5. `web_vuln` — nuclei + nikto + **sqlmap** and **dalfox** against parameterized endpoints, with the cookie from step 4 auto-injected
6. `wordpress` — wpscan (if WordPress detected)
7. `api_fuzzer` — API surface + BOLA/BFLA hints
8. `auth` — auth-bypass + SSO/OAuth misconfig
9. `report` — deterministic Markdown consolidator

**Full help** (all flags and behaviours):
```bash
python harness.py --help
```

---

## Trying it against known-vulnerable targets

Instead of a real bug-bounty scope, spin up a lab container:

**OWASP Juice Shop** (Node.js + Angular SPA — CTF-style vulns):
```bash
docker run --rm -d --name juice -p 3000:3000 bkimminich/juice-shop
# Point the harness at:  http://localhost:3000/
docker kill juice   # stop
```

**DVWA** (PHP classic — CVE-style vulns, easier to detect):
```bash
docker run --rm -d --name dvwa -p 8080:80 vulnerables/web-dvwa
# First open http://localhost:8080/setup.php → "Create/Reset Database"
# Point the harness at:  http://localhost:8080/
docker kill dvwa
```

---

## Configuration summary

Everything lives in `config.yaml`. Key sections:

| Section | Purpose |
|---|---|
| `llm.*` | LLM backend + model + API key |
| `min_request_interval_sec` | Global rate limit (default 1 req/s) |
| `shell_timeout_sec` | Per-command timeout (default 300 s) |
| `custom_headers` | HTTP headers attached to every request (attribution) |
| `scope_file` / `scope_enforcement` | In-scope allowlist file + mode (strict/warn/off) |
| `oob_host` | Your self-hosted OOB catcher (for blind vuln PoCs) |
| `smtp.*` | Email destination (with `default_to` for automatic send) |
| `telegram.*` | Telegram bot token + chat_id |
| `notify_only_if_findings` | Only send email + Telegram if run produced findings |
| `cleanup_tempfiles` | Wipe `/tmp/harness-*` etc. after each run |

See `config.example.yaml` inline comments for every field.

---

## Operational rules (built into the harness)

- **Rate limit** enforced at the tool layer for EVERY HTTP request / shell command. The model cannot bypass.
- **Scope allowlist** cotejado antes de cada request (host/wildcard/CIDR/IP). Off-scope → error (strict mode) or warning (warn mode).
- **Shell allowlist** — only pre-approved binaries (`nmap nuclei ffuf curl dig …`) can run. Destructive commands (`rm`, `sudo`, `mv`, `chmod`, backticks, `$(…)`) are hard-denied.
- **Output redaction** — `redact.py` scrubs JWT / AWS keys / GitHub tokens / cookies / emails from every tool output before it reaches the model or the report.
- **Pre-flight reachability check** — the orchestrator sends a single HTTP GET to the target before spawning any agent; if the target is unreachable, the pipeline is aborted and REPORT.md carries a `🚨 TARGET UNREACHABLE` banner.
- **Cleanup** — temp files created by the agents (`/tmp/harness-*`, `/tmp/gau_*`, `/tmp/nuclei_*`, …) are wiped after each run.

---

## Directory layout

```
bughunter-harness/
├── harness.py             CLI entry point + REPL + argparse
├── orchestrator.py        Multi-agent pipeline
├── llm_backend.py         Backend auto-detect + resolve
├── mailer.py              SMTP (auth + local relay)
├── telegram_notifier.py   Telegram Bot API
├── tempcleaner.py         /tmp cleanup
├── tools.py               http_get / http_post / run_shell + gates
├── scope.py               In-scope allowlist parser
├── throttle.py            Global rate limiter
├── redact.py              Secret redaction
├── progress.py            Spinner
├── shared_state.py        Cross-agent state.json
├── ui.py                  rich multi-agent progress panel
├── requirements.txt
├── config.example.yaml    Template (COPY to config.yaml and edit)
├── scope.example.txt      Template (COPY to scope.txt and edit)
├── launch.example.command Sample macOS launcher
│
├── agents/
│   ├── base.py            BaseAgent (LLM ↔ tools loop)
│   ├── recon.py
│   ├── fingerprint.py
│   ├── content_discovery.py
│   ├── login_probe.py     LAB-only default-cred probe → session_cookies
│   ├── web_vuln.py        nuclei + nikto + sqlmap + dalfox
│   ├── wordpress.py
│   ├── api_fuzzer.py
│   ├── auth.py
│   └── report.py          Markdown consolidator (deterministic, no LLM)
│
└── sessions/              Auto-generated per run (in .gitignore)
    └── <YYYYMMDDTHHMMSSZ>/
        ├── state.json     Cross-agent shared state
        ├── REPORT.md      Final markdown report
        └── agents/
            └── <agent>.jsonl   Full turn-by-turn trace per agent
```

---

## Troubleshooting

- **"Cloud backend selected but no API key found"** — set `llm.api_key` in `config.yaml` or export the backend's default env var (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `NVIDIA_API_KEY`, `GEMINI_API_KEY`).
- **"Local SMTP relay not reachable at 127.0.0.1:25"** — either configure a real SMTP provider or install Mailpit (see §6 above).
- **"Model returned no tool call after 3 retries"** — enable "Tool Use" in your LM Studio model settings, or switch to `tool_choice: "auto"` in `config.yaml`.
- **"command timed out after 300s"** — raise `shell_timeout_sec` in `config.yaml`, or tell the model to reduce scope (fewer nuclei tags, smaller wordlist).
- **`ffuf` fails with "wordlist not found"** — install SecLists (see §5 above).
- **`bash: nuclei: command not found`** — install the offensive tools (see §4 above).
- **`bash: sqlmap: command not found` / `bash: dalfox: command not found`** — install them: `brew install sqlmap` + `go install github.com/hahwul/dalfox/v2@latest` (Linux: `sudo apt install sqlmap`). Without them the `web_vuln` agent skips step 6 (active parameter injection) and you will miss SQLi / XSS in custom code.
- **`login_probe` never captures a cookie on my real bug-bounty target** — that agent runs ONLY against clearly-labeled LAB targets (localhost / private IP / DVWA / Juice Shop / Mutillidae / bWAPP / WebGoat). This is intentional: hunting default credentials on a real target = brute-force + duplicate + policy violation in almost every program. Bring your own valid session cookie via the `--header 'Cookie: …'` REPL flag if you have authorized access.

---

## License

MIT. See `LICENSE`.

## Disclaimer

Use only against systems you are **explicitly authorized** to test — your own labs, HTB / TryHackMe / CTFs, or bug-bounty programs where the target is in scope. The `scope_enforcement: strict` default is there to help; do not disable it lightly. The authors and contributors accept no liability for misuse.
