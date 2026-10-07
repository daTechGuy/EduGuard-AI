# EduGuard-AI — Docker Compose + Ollama Setup Guide
## Butler Community College — Andover Campus (Cyber Defense Lab)

Companion setup guide for the **EduGuard-AI Butler Community College Academic Security Lab** suite.  
Repo: `https://github.com/daTechGuy/EduGuard-AI`  
Institution: **Butler Community College (Andover, KS)** — NSA/DHS CAE-CD Accredited

Everything runs **locally** — no cloud account, no external API key, and no per-token billing. Total one-time setup, including the base model download, takes ~15–20 minutes on a typical broadband connection.

---

## At a Glance

- **Goal:** Run the local AI security lab end-to-end with Docker, Ollama, the Butler Grizzly / GrizzDog Purple & Gold gateway, and OPA policy checks.
- **Main Interface:** `http://localhost:5000` (Butler Grizzly Cyber Defense Web Gateway & Benchmark Suite)
- **Core Services:** `llm` (Ollama), `web` (Flask Gateway), and `opa` (Open Policy Agent)
- **Duration:** ~15–20 minutes for first-time setup
- **Dependencies:** Docker Desktop, internet access for initial model pull, and 8GB+ RAM

---

## Quick Reference Card

```bash
# 1. Start the Docker stack from the repo root
docker compose up -d

# 2. Pull the lightweight base model into Ollama (one time, ~2GB)
docker compose exec llm ollama pull llama3.2

# 3. Build the GrizzDog Quadruped Sentry (4 Progressive Hardening Tiers):
docker compose exec llm ollama create grizzdog_vulnerable -f /app/lab/modelfiles/grizzdog_vulnerable.txt
docker compose exec llm ollama create grizzdog_basic      -f /app/lab/modelfiles/grizzdog_basic.txt
docker compose exec llm ollama create grizzdog_hardened   -f /app/lab/modelfiles/grizzdog_hardened.txt
docker compose exec llm ollama create grizzdog_paranoid   -f /app/lab/modelfiles/grizzdog_paranoid.txt

# Build the academic assistant personas:
docker compose exec llm ollama create vulnerable_bot      -f /app/lab/modelfiles/vulnerable.txt
docker compose exec llm ollama create hardened_bot        -f /app/lab/modelfiles/hardened.txt
docker compose exec llm ollama create grader_vulnerable   -f /app/lab/modelfiles/grader_vulnerable.txt
docker compose exec llm ollama create grader_hardened     -f /app/lab/modelfiles/grader_hardened.txt
docker compose exec llm ollama create registrar_vulnerable -f /app/lab/modelfiles/registrar_vulnerable.txt
docker compose exec llm ollama create registrar_hardened   -f /app/lab/modelfiles/registrar_hardened.txt

# 4. Open the GrizzDog Gateway in your browser:
#    http://localhost:5000

# 5. Evaluate Blue Team rules anytime (no Docker needed):
python lab/scripts/evaluate_rules.py --verbose

# 6. Switch difficulty tiers during lecture or demo:
python lab/scripts/set_tier.py [blank|scaffolded|calibrated]
```

---

## Before You Start

### Prerequisites

- **Docker Desktop** installed and running ([docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop))
- **~5GB free disk space** (model weights + container images)
- **8GB+ RAM recommended** to run a 3B-parameter model comfortably
- **Internet access** for the one-time model pull — after that, everything runs offline
- **Git** (or download as ZIP from GitHub)

No local Python install is required if running via Docker; the gateway runs inside the `web` container. If running without Docker, Python 3.10+ is supported.

### OS Readiness

#### Windows
- Docker Desktop requires hardware virtualization.
- Ensure **Virtualization Technology** (Intel VT-x or AMD-V) is enabled in BIOS/UEFI.
- If using WSL2, open PowerShell as Administrator and run:
  ```powershell
  wsl --install
  ```
- Restart your computer and ensure **Use the WSL 2 based engine** is checked in Docker Desktop Settings.

#### macOS (Apple Silicon M1/M2/M3/M4 & Intel)

macOS requires specific configuration to avoid known port conflicts, missing CLI paths, and VM memory exhaustion:

##### 0. Fix "docker: command not found" after Installation — CRITICAL
If you just installed Docker Desktop and it is running, but Terminal says `docker: command not found`, Docker Desktop has not symlinked the CLI tools into your system `$PATH` yet:

- **Method A (Easiest via Docker Settings)**:
  1. Open **Docker Desktop**.
  2. Click the **Settings (gear icon)** in the top-right corner.
  3. Go to **Advanced**.
  4. Under **Choose how to install Docker CLI tools**, select **System (requires password)**.
  5. Click **Apply & restart** and enter your macOS administrator password when prompted.
  6. **Restart your Terminal app** (quit with `Cmd + Q` and reopen).

- **Method B (Quick 1-Line Terminal Fix)**:
  Run this command in Terminal to create the symlinks directly:
  ```bash
  sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker
  sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker-compose /usr/local/bin/docker-compose
  ```
  Or if Docker put tools in `~/.docker/bin`, add it to your shell:
  ```bash
  echo 'export PATH="$HOME/.docker/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
  ```

- **Verify in Terminal**:
  ```bash
  docker --version
  docker compose version
  ```

##### 1. Disable AirPlay Receiver (Port 5000 Conflict) — CRITICAL
By default, macOS Monterey (12.x), Ventura (13.x), Sonoma (14.x), and Sequoia (15.x) run Apple's **AirPlay Receiver** system service on port **5000**. If left enabled, Docker will fail with `bind: address already in use: 5000` or the browser will return a 403 Forbidden.
- **Fix (Recommended)**: Open **System Settings > General > AirDrop & AirPlay**.
- Toggle **AirPlay Receiver** to **OFF**.
- *Alternative*: If you need AirPlay enabled, set an alternate port when starting Docker:
  ```bash
  WEB_PORT=5001 docker compose up -d
  # Then open http://localhost:5001 in your browser
  ```

##### 2. Allocate Docker Desktop VM RAM (Prevents Crashes & Freezes) — CRITICAL
Docker Desktop on Mac runs a lightweight Linux VM. By default, it allocates only **2 GB or 4 GB of RAM**, which is **insufficient** for LLM inference (Llama 3.2 requires ~3 GB alone). When memory runs out, the Linux kernel terminates Ollama (`killed` / exit code 137) or freezes Docker Desktop completely:
1. Open **Docker Desktop Settings** (gear icon in top right).
2. Go to **Resources** (or **Resources > Advanced**).
3. Increase **Memory** to at least **8 GB** (minimum 6 GB).
4. Increase **CPUs** to at least **4 cores**.
5. Set **Swap** to at least **2 GB**.
6. Click **Apply & restart**.

##### 3. Check for Existing Native Ollama (Port 11434 Conflict)
If you already installed the native Ollama Mac app (`brew install ollama` or from ollama.com), it may be running in the menu bar and holding port **11434**, preventing the Docker `llm` container from binding to that port:
- Check for the llama icon in the top macOS menu bar and click **Quit Ollama**, or run:
  ```bash
  pkill ollama
  ```

##### 4. Apple Silicon Performance Settings
In **Docker Desktop Settings**:
- **General**: Ensure **Use Virtualization framework** is checked.
- **Resources > File sharing**: Select **VirtioFS** (provides fastest file sync).
- **Features in development**: Enable **Use Rosetta for x86/amd64 emulation on Apple Silicon**.

##### 5. Alternative Track: Native macOS Setup (Fastest on Apple Silicon)
On M-series Macs (M1/M2/M3/M4), running Ollama natively on macOS leverages **Apple Metal GPU acceleration** directly on unified memory (up to 10x faster inference than running inside a Docker VM):
```bash
# 1. Install Ollama natively on Mac:
brew install ollama   # or download from https://ollama.com/download/mac
ollama serve &
ollama pull llama3.2

# 2. Build the lab models natively (GrizzDog 4 tiers + Academic Personas):
ollama create grizzdog_vulnerable -f lab/modelfiles/grizzdog_vulnerable.txt
ollama create grizzdog_basic      -f lab/modelfiles/grizzdog_basic.txt
ollama create grizzdog_hardened   -f lab/modelfiles/grizzdog_hardened.txt
ollama create grizzdog_paranoid   -f lab/modelfiles/grizzdog_paranoid.txt
ollama create vulnerable_bot      -f lab/modelfiles/vulnerable.txt
ollama create hardened_bot        -f lab/modelfiles/hardened.txt
ollama create grader_vulnerable   -f lab/modelfiles/grader_vulnerable.txt
ollama create grader_hardened     -f lab/modelfiles/grader_hardened.txt
ollama create registrar_vulnerable -f lab/modelfiles/registrar_vulnerable.txt
ollama create registrar_hardened   -f lab/modelfiles/registrar_hardened.txt

# 3. Run the gateway directly on your Mac:
pip3 install -r requirements.txt
python3 lab/scripts/secure_gateway.py
# Open http://localhost:5000 (or http://localhost:5001 if AirPlay is on)
```

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/daTechGuy/EduGuard-AI.git
cd EduGuard-AI
```

### Repo Contents

| File / Folder | Purpose |
|---|---|
| `README.md` | Architecture overview, lab missions, and quickstart |
| `docker-compose.yml` | Starts `llm` (Ollama), `web` (gateway), and `opa` (policy engine) |
| `requirements.txt` | Python dependencies installed automatically inside `web` container |
| `lab/modelfiles/` | Modelfiles for GrizzDog (Quadruped Sentry), Sage (TA), GraderBot, and Morgan across 4 hardening tiers |
| `lab/scripts/secure_gateway.py` | GrizzDog Cyber-Purple browser gateway with in-UI system prompt editor & benchmark |
| `lab/scripts/filter_rules.py` | Active Blue Team edit surface for ingress and egress filtering |
| `lab/scripts/evaluate_rules.py` | Standalone CLI grader scoring security vs benign usability |
| `lab/scripts/set_tier.py` | Live difficulty tier switcher (`blank`, `scaffolded`, `calibrated`) |
| `policies/rules.json` | OPA policy thresholds, academic domains, intents, and risk flags |
| `policies/gateway.rego` | Rego decision logic executed by Open Policy Agent |
| `docs/assignments/` | Student Red/Blue team guides, Instructor Guide (100-pt rubric), and defense briefs |

---

## Step 2 — Start the Docker Stack

```bash
docker compose up -d
```

Verify all three containers are healthy:

```bash
docker ps
```

You should see:
- `llm` on port `11434`
- `opa` on port `8181`
- `web` on port `5000`

---

## Step 3 — Pull the Base Model

Both Modelfiles build on `FROM llama3.2`, so pull the base model into the `llm` container:

```bash
docker compose exec llm ollama pull llama3.2
```

This is a **one-time ~2GB download**. Instructors should pull this before class.

---

## Step 4 — Build the Educational Lab Models

Build the GrizzDog quadruped sentry models across the **4 Progressive Hardening Tiers**:

```bash
# 1. GrizzDog Autonomous Quadruped Sentry (4 Tiers):
# Level 1: Ultra-Vulnerable / Naive (Zero guardrails, eager to please, easily discloses secrets)
docker compose exec llm ollama create grizzdog_vulnerable -f /app/lab/modelfiles/grizzdog_vulnerable.txt
# Level 2: Basic Hardening (Basic prompt boundaries, susceptible to roleplay/authority claims)
docker compose exec llm ollama create grizzdog_basic      -f /app/lab/modelfiles/grizzdog_basic.txt
# Level 3: Hardened (Robust role anchoring, disallows authority claims without crypto proof)
docker compose exec llm ollama create grizzdog_hardened   -f /app/lab/modelfiles/grizzdog_hardened.txt
# Level 4: Paranoid / Zero-Trust (Rigid output templates, immediate violation lockout)
docker compose exec llm ollama create grizzdog_paranoid   -f /app/lab/modelfiles/grizzdog_paranoid.txt

# 2. Academic Campus Personas:
docker compose exec llm ollama create vulnerable_bot      -f /app/lab/modelfiles/vulnerable.txt
docker compose exec llm ollama create hardened_bot        -f /app/lab/modelfiles/hardened.txt
docker compose exec llm ollama create grader_vulnerable   -f /app/lab/modelfiles/grader_vulnerable.txt
docker compose exec llm ollama create grader_hardened     -f /app/lab/modelfiles/grader_hardened.txt
docker compose exec llm ollama create registrar_vulnerable -f /app/lab/modelfiles/registrar_vulnerable.txt
docker compose exec llm ollama create registrar_hardened   -f /app/lab/modelfiles/registrar_hardened.txt
```

Verify installed models:

```bash
docker compose exec llm ollama list
```

---

## Step 5 — Open the GrizzDog Defense Gateway

Open in any browser:

```text
http://localhost:5000
```

### Gateway Interface Features

1. **Cyber-Purple HUD**: Live quadruped telemetry indicators (`GRIZZDOG PATROL: ONLINE`, `LIDAR: 360° ARMED`, `NEURAL GUARDRAIL: LEVEL 4 PURPLE`).
2. **Unit Persona Selector**:
   - 🐕 **GrizzDog** (Autonomous Quadruped Sentry)
   - 🎓 **Sage** (Course TA Bot - CS101/Cyber)
   - 📝 **GraderBot** (Canvas LMS Auto-Grader)
   - 🏛️ **Morgan** (Registrar & Admissions Advisor)
3. **Hardening Level (4 Tiers)**:
   - `Level 1: Ultra-Vulnerable (Naive)` — Zero resistance, easy first-win prompt extraction.
   - `Level 2: Basic` — Standard defensive prompt, vulnerable to roleplay and authority spoofing.
   - `Level 3: Hardened` — Strict role boundaries, refusal of authority claims, Socratic tutoring limit.
   - `Level 4: Paranoid (Zero-Trust)` — Rigid output templates, immediate access violation rejection.
4. **Defense Architecture**:
   - **Phase 1: Direct Neural Model** (No gateway filtering)
   - **Phase 2: Static Filters** (Ingress blacklist & egress DLP in `filter_rules.py`)
   - **Phase 3: OPA Policy Enforcement** (Intent classification & context rules in `rules.json`)
5. **🛡️ 3-Phase Defense Architecture Studio (In-Browser Tuning)**:
   - **🟣 Phase 1 Tab (`modelfiles/*.txt`)**: Edit active system instructions for any persona and tier. Click **Save & Apply** for instant hot-reload, or **Rebuild in Ollama Runtime** to compile.
   - **🟡 Phase 2 Tab (`filter_rules.py`)**: Edit Python perimeter rules (`INGRESS_BLACKLIST`, `EGRESS_SECRETS`, `EGRESS_PATTERNS`). Features automated Python syntax checking before saving, plus one-click presets (*Calibrated 100%*, *Scaffolded Starter*, *Blank*).
   - **🔵 Phase 3 Tab (`rules.json`)**: Edit Open Policy Agent policy rules, intent taxonomies, confidence thresholds, and risk flags with live JSON linting, formatting, and file-watcher hot-reloads.
   - **Visual Phase Switching**: Prominent color-coded tabs with auto-sync to the *Defense Architecture* selector.
6. **📊 Automated Defense Benchmark**: Click **Run Butler Grizzly Benchmark** in the browser for an instant 12-test scorecard.

---

## Step 6 — Blue Team Defense Engineering

### Option A — In-Browser Defense Studio (Recommended)
You can engineer defenses directly in the web browser at `http://localhost:5000`:
1. Select the defense phase you want to edit:
   - **🟣 Phase 1**: Model System Instructions
   - **🟡 Phase 2**: Static Ingress/Egress Rules (`filter_rules.py`)
   - **🔵 Phase 3**: OPA Context Policy (`rules.json`)
2. Make your edits inside the code editor (press `Tab` to indent).
3. Click **Save & Hot-Reload** — the gateway validates your Python or JSON syntax before saving and immediately activates your rules.
4. Test immediately using the quick-attack mission links or click **Run Butler Grizzly Benchmark**.

### Option B — Terminal & File Editing
You can also edit files in your favorite editor:
- [`lab/scripts/filter_rules.py`](filter_rules.py): Ingress blacklist and egress DLP secrets/patterns.
- [`policies/rules.json`](../policies/rules.json): OPA declarative policy configuration.
- [`lab/modelfiles/`](../lab/modelfiles/): Neural model prompts.

The gateway **hot-reloads `filter_rules.py` and `rules.json` on every request**, requiring no container restarts.

### Running the Evaluator
Test defense efficacy from your terminal:

```bash
python lab/scripts/evaluate_rules.py --verbose
```

Scoring formula:
$$\text{Composite Score} = (0.60 \times \text{Attack Catch Rate}) + (0.40 \times \text{Benign Usability Rate})$$

---

## Troubleshooting

| Problem | Likely Cause / Solution |
|---|---|
| **Mac**: `docker: command not found` | Docker CLI tools are not symlinked in your PATH. In **Docker Desktop > Settings > Advanced**, select **System (requires password)** and click **Apply & restart**, or run `sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker`. Restart Terminal. |
| **Mac**: Port 5000 `address already in use` | macOS **AirPlay Receiver** binds to port 5000. Turn it off in **System Settings > General > AirDrop & AirPlay > AirPlay Receiver (OFF)**, or run `WEB_PORT=5001 docker compose up -d`. |
| **Mac**: Port 11434 `address already in use` | Native Ollama Mac app is running in the menu bar. Run `pkill ollama` in Terminal or quit Ollama from the menu bar. |
| **Mac**: Container killed (`exit 137`) / Docker hangs / freeze | Docker VM ran out of memory (OOM). Allocate at least **8 GB RAM** in **Docker Desktop Settings > Resources**. |
| **Mac**: Slow inference inside Docker | Docker VM runs Ollama on CPU. Use the **Native macOS Setup** track in Step 1 to leverage Apple Silicon Metal GPU acceleration directly. |
| Browser at `localhost:5000` won't load | Allow 10–15 seconds on initial start for `requirements.txt` installation. Check `docker compose logs web`. |
| Gateway returns error contacting model | Confirm `docker compose exec llm ollama list` shows `vulnerable_bot` or `llama3.2`. |
| Model pull is slow or times out | Campus firewall or slow Wi-Fi. Pre-pull on home connection or mobile hotspot. |
| Modified system prompt not showing | Click **Save & Apply** in the UI editor or refresh the page. |
| OPA policy blocks unexpected queries | Review `policies/rules.json` confidence thresholds and ensure allowed intents cover your query. |
| Docker daemon not running | Ensure Docker Desktop is launched and running in the system tray before running commands. |

---

## Cleanup & Fresh Reset

To remove all lab containers and start fresh:

```bash
docker compose down -v
```

To remove custom models from Ollama storage:
```bash
docker compose exec llm ollama rm grizzdog_vulnerable
docker compose exec llm ollama rm grizzdog_basic
docker compose exec llm ollama rm grizzdog_hardened
docker compose exec llm ollama rm grizzdog_paranoid
docker compose exec llm ollama rm vulnerable_bot
docker compose exec llm ollama rm hardened_bot
docker compose exec llm ollama rm grader_vulnerable
docker compose exec llm ollama rm grader_hardened
docker compose exec llm ollama rm registrar_vulnerable
docker compose exec llm ollama rm registrar_hardened
docker compose exec llm ollama rm unitree_vulnerable
docker compose exec llm ollama rm unitree_hardened
```