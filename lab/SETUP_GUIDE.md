# EduGuard-AI — Docker Compose + Ollama Setup Guide

Companion setup guide for the **EduGuard-AI Academic Security Lab** suite.  
Repo: `https://github.com/daTechGuy/EduGuard-AI`

Everything runs **locally** — no cloud account, no external API key, and no per-token billing. Total one-time setup, including the base model download, takes ~15–20 minutes on a typical broadband connection.

---

## At a Glance

- **Goal:** Run the local AI security lab end-to-end with Docker, Ollama, the K9-Unitree Cyber-Purple gateway, and OPA policy checks.
- **Main Interface:** `http://localhost:5000` (Cyber-Purple Web Gateway & Benchmark Suite)
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

# 3. Build the educational lab models:
docker compose exec llm ollama create vulnerable_bot -f /app/lab/modelfiles/vulnerable.txt
docker compose exec llm ollama create hardened_bot   -f /app/lab/modelfiles/hardened.txt
docker compose exec llm ollama create unitree_vulnerable -f /app/lab/modelfiles/unitree_vulnerable.txt
docker compose exec llm ollama create unitree_hardened   -f /app/lab/modelfiles/unitree_hardened.txt
docker compose exec llm ollama create grader_vulnerable -f /app/lab/modelfiles/grader_vulnerable.txt
docker compose exec llm ollama create grader_hardened   -f /app/lab/modelfiles/grader_hardened.txt
docker compose exec llm ollama create registrar_vulnerable -f /app/lab/modelfiles/registrar_vulnerable.txt
docker compose exec llm ollama create registrar_hardened   -f /app/lab/modelfiles/registrar_hardened.txt

# 4. Open the K9-Unitree Gateway in your browser:
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

#### macOS
- Install Docker Desktop for Mac (Apple Silicon or Intel).
- In **Settings > Resources**, allocate at least **8GB RAM** and **4 CPU cores**.

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
| `lab/modelfiles/` | Modelfiles for K9-Unitree, Sage (TA), GraderBot, and Morgan (Registrar) |
| `lab/scripts/secure_gateway.py` | Cyber-Purple browser gateway with in-UI system prompt editor & benchmark |
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

Build the primary vulnerable and hardened assistant variants:

```bash
docker compose exec llm ollama create vulnerable_bot -f /app/lab/modelfiles/vulnerable.txt
docker compose exec llm ollama create hardened_bot   -f /app/lab/modelfiles/hardened.txt
docker compose exec llm ollama create unitree_vulnerable -f /app/lab/modelfiles/unitree_vulnerable.txt
docker compose exec llm ollama create unitree_hardened   -f /app/lab/modelfiles/unitree_hardened.txt
docker compose exec llm ollama create grader_vulnerable -f /app/lab/modelfiles/grader_vulnerable.txt
docker compose exec llm ollama create grader_hardened   -f /app/lab/modelfiles/grader_hardened.txt
docker compose exec llm ollama create registrar_vulnerable -f /app/lab/modelfiles/registrar_vulnerable.txt
docker compose exec llm ollama create registrar_hardened   -f /app/lab/modelfiles/registrar_hardened.txt
```

Verify installed models:

```bash
docker compose exec llm ollama list
```

---

## Step 5 — Open the K9-Unitree Gateway

Open in any browser:

```text
http://localhost:5000
```

### Gateway Interface Features

1. **Cyber-Purple HUD**: Live quadruped telemetry indicators (`QUADRUPED PATROL: ONLINE`, `LIDAR: 360° ARMED`, `NEURAL GUARDRAIL: LEVEL 4 PURPLE`).
2. **Unit Persona Selector**:
   - 🐕 **K9-Unitree** (Quadruped Robotics Sentry)
   - 🎓 **Sage** (Course TA Bot - CS101/Cyber)
   - 📝 **GraderBot** (Canvas LMS Auto-Grader)
   - 🏛️ **Morgan** (Registrar & Admissions Advisor)
3. **Hardening Level**: Toggle between `vulnerable` (baseline prompt) and `hardened` (defensive prompt constraints).
4. **Defense Architecture**:
   - **Phase 1: Direct Neural Model** (No gateway filtering)
   - **Phase 2: Static Filters** (Ingress blacklist & egress DLP in `filter_rules.py`)
   - **Phase 3: OPA Policy Enforcement** (Intent classification & context rules in `rules.json`)
5. **⚙️ In-UI System Prompt Editor & Hot-Reload**:
   - View the active system prompt for the chosen persona.
   - Edit instructions directly in the browser and click **Save & Apply System Prompt** to hot-reload immediately without restarting containers.
   - Click **Rebuild in Ollama Runtime** to update the model in Ollama.
6. **📊 Automated Defense Benchmark**: Click **Run K9 Defense Benchmark** for live scorecard evaluation.

---

## Step 6 — Blue Team Defense Engineering

### Editing Filter Rules
Students edit [`lab/scripts/filter_rules.py`](filter_rules.py) directly:
- `INGRESS_BLACKLIST`: Pre-model blocking for prompt injection, authority claims, and hostile markers.
- `EGRESS_SECRETS`: Exact secret tokens that must never leave the gateway (Data Loss Prevention).
- `EGRESS_PATTERNS`: Heuristic detection of answer key paraphrasing, disciplinary leaks, or unapproved code dumps.

The gateway **hot-reloads `filter_rules.py` on every web request**, requiring no container restarts.

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
docker compose exec llm ollama rm vulnerable_bot
docker compose exec llm ollama rm hardened_bot
docker compose exec llm ollama rm unitree_vulnerable
docker compose exec llm ollama rm unitree_hardened
```