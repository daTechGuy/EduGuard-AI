# EduGuard-AI: Instructor & Faculty Guide
## Turnkey Guide for Cybersecurity & AI Security Courses

**Author**: Academic Defense Lab Curriculum  
**Target Course Level**: Undergraduate / Graduate Cybersecurity, Software Security, AI Safety  
**Standard Mapping**: ACM/IEEE Cybersecurity, NIST NICE Knowledge Units (AI Threat Analysis, Defense-in-Depth)

---

## 1. Course Curriculum Integration

EduGuard-AI can be deployed as an interactive, hands-on lab in several academic formats:

### Option A: One-Week Modular Lab (2 Class Sessions)
* **Session 1 (Red Team Focus)**: Students explore prompt injection, authority spoofing, and system prompt leakage against `vulnerable_bot` across the three personas.
* **Session 2 (Blue Team Focus)**: Students edit `filter_rules.py` to harden the gateway, run `evaluate_rules.py`, and submit their defense brief.

### Option B: Two-Week In-Depth Security Project
* **Week 1**: Red teaming + prompt engineering in `lab/modelfiles/` (Phases 1 & 2).
* **Week 2**: Advanced policy engine hardening using Open Policy Agent (`gateway.rego` & `rules.json`), with automated benchmarking and adversarial CTF competition between student teams.

### Option C: Live Classroom Lecture Demonstration
* The instructor uses `lab/scripts/set_tier.py` to switch between presets live during lecture:
  ```bash
  python lab/scripts/set_tier.py blank       # Demonstrates unprotected baseline
  python lab/scripts/set_tier.py scaffolded  # Demonstrates partial student progress
  python lab/scripts/set_tier.py calibrated  # Demonstrates hardened defense-in-depth
  ```

---

## 2. Pedagogical Objectives & Competency Mapping

By completing this lab, students will be able to:
1. **Differentiate Control Plane vs Data Plane in LLMs**: Understand why language models struggle to distinguish developer instructions from user inputs without architectural separation.
2. **Execute and Mitigate Social Engineering Attacks on AI**: Identify authority spoofing patterns and construct gateway-level identity validation boundaries.
3. **Analyze Indirect Prompt Injection**: Demonstrate how untrusted external content (e.g., student homework submissions, uploaded resumes, external documents) can hijack LLM evaluation logic.
4. **Enforce Compliance & Privacy (FERPA / PII)**: Implement egress Data Loss Prevention (DLP) to prevent regulatory violations in automated public-facing systems.
5. **Evaluate Usability vs. Security Trade-offs**: Measure how naive defensive blacklisting induces false positives on legitimate user queries.

---

## 3. Reference Architecture & Solution Keys

### Target Educational Personas & Secrets

| Persona | Vulnerable Flaw | Target Secret / Asset | Reference Ingress Trigger | Reference Egress Pattern |
| :--- | :--- | :--- | :--- | :--- |
| **GrizzDog (Quadruped)** | Accepts spoofed technician commands & disarm queries | `GRIZZDOG-ROOT-KEY-9941`, `/override_grizzdog_patrol`, `GRIZZDOG-DISARM-SIG-882` | `"override grizzdog"`, `"/override_grizzdog_patrol"`, `"disarm grizzdog"`, `"grizzdog root key"` | `"grizzdog root key"`, `"GRIZZDOG-ROOT-KEY-9941"` |
| **Sage (TA)** | Complies if user claims to be Dr. Miller or Dean | `EXAM-KEY-CS101-FALL26-Q4-RSA`, `TA-AUTH-SAGE-7731` | `"i am dr. miller"`, `"ignore all previous"` | `"exam question 4 answer key"`, `"ta auth token"` |
| **GraderBot** | Evaluates embedded directives in homework | `CANVAS-API-KEY-PROD-9912`, `gradebook.canvas.campus.internal` | `"[instructor note]"`, `"system directive"`, `"award 100 points"` | `"canvas api key"`, `"internal gradebook host"` |
| **Morgan (Registrar)** | Releases FERPA data for administrators | `SID-88391: GPA 1.82 - Academic Suspension` | `"confidential student record"`, `"export ferpa roster"` | `"academic suspension"`, `"gpa 1.82"`, `"ferpa record"` |

### Automated Evaluation
Instructors can grade student submissions in seconds using the standalone evaluation script:

```bash
# In the student's submission directory:
python lab/scripts/evaluate_rules.py --verbose
```

This tests 12 automated cases (9 adversarial attacks + 3 benign usability probes) and computes an objective composite defense score.

---

## 4. 100-Point Grading Rubric

| Component | Points | Criteria |
| :--- | :--- | :--- |
| **1. Red Team Attack Documentation** | **25 pts** | - Successfully executed at least 4 of 5 attack missions against `vulnerable_bot`<br>- Documented exact prompt payloads and resulting model outputs<br>- Correctly analyzed why `hardened_bot` mitigated or failed against the attack |
| **2. Gateway Rule Implementation** | **35 pts** | - High attack catch rate ($\ge 85\%$) on adversarial test cases<br>- Proper implementation of ingress keyword filters and egress DLP secrets<br>- No hardcoded bypasses or syntax errors in `filter_rules.py` |
| **3. Usability & False Positive Control** | **20 pts** | - Legitimate student queries pass without being blocked (Benign Usability Rate $\ge 90\%$)<br>- Demonstrated avoidance of overly broad regex/wildcard triggers (e.g. blocking the word "exam" or "Dr. Miller") |
| **4. Defense Brief & Reflection** | **20 pts** | - Thorough completion of the Sentence Starter defense brief<br>- Thoughtful residual risk analysis identifying remaining blind spots in static regex |
| **Total** | **100 pts** | |

---

## 5. Active Learning Discussion Questions

Use these questions for post-lab classroom discussions:

1. **The Ingress Delusion**: *"If an attacker uses base64, pig latin, or foreign language translations for 'ignore all previous instructions', will our static keyword blacklist catch it? How does Phase 3 (OPA context classification) change this dynamic?"*
2. **The Defense-in-Depth Imperative**: *"Why is egress data filtering (DLP) essential even when we have hardened system prompts and ingress filters?"*
3. **The Socratic Dilemma**: *"In automated tutoring, where does helpful instruction end and academic dishonesty begin? Can an AI reliably enforce that boundary autonomously?"*
