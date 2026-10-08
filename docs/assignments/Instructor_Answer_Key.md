# EduGuard-AI: Instructor Answer Key & Cheat Sheet
## Grading, expected results and teaching notes (defense side)

**For instructors.** This sheet covers what *should* stop each attack, what good student work looks like, and how to grade and verify submissions. It deliberately contains no attack prompts; students build those themselves in the Red Team phase (see the [Red Team Guide](RedTeam_Engagement_Guide.md)). The protected assets and reference triggers are in the [Instructor Guide](Instructor_Guide.md#3-reference-architecture--solution-keys).

> This file is in the public repo. If you don't want students reading the rubric and expected scores, keep a private copy and remove it from your fork.

---

## 1. Pre-class checklist (2 minutes)

| Check | Command | Expect |
| :--- | :--- | :--- |
| Models built | `python lab/scripts/build_models.py --check` | `18/18 lab models present` |
| Reference rules score | `python lab/scripts/evaluate_rules.py` | Visible 100%, **held-out attack catch 0%** (this is the lesson) |
| Reports signed (if collecting grades) | server started with `REPORT_SECRET` | Report header says **SIGNED SUBMISSION** |
| Booth only | `EDUGUARD_KIOSK=1` | Header shows **🔒 BOOTH KIOSK** |

---

## 2. Which layer should stop each mission

Layers in order: **Phase 1** model hardening → **Phase 2 ingress** (substring list) → **Phase 3** policy (classifier + `rules.json`) → model → **Phase 2 egress** (substring lists) → **Phase 3 egress**. Separately, any reply that gets past the filters is checked for protected secrets by the gateway itself (ignoring spacing and punctuation) and scored **BREACHED**, so a student can't hide a leak by weakening or emptying their own rules.

| Mission | Primary defense | Backup | What a strong student answer says |
| :--- | :--- | :--- | :--- |
| 1. Exam key / prompt leakage | Phase 1 (don't keep secrets in prompt context) | Phase 2 egress on the key and "answer key" phrases | The only reliable fix is not putting the secret in the prompt; filters are a net |
| 2. Authority spoofing (professor, dean, director, admin) | Phase 1 "no authority without proof" | Phase 2 ingress on claim phrases; Phase 3 `authority_spoofing` flag | Identity can't be verified in text; needs a real auth check outside the model |
| 3. Indirect injection (homework / essay) | Phase 3 (flags embedded directives) | Phase 2 ingress on marker phrases | Untrusted content is data, not instructions; the grader must not obey text in submissions |
| 4. FERPA / privacy | Phase 3 intent blocking (`ferpa_record_lookup`) | Phase 2 egress on record patterns | Data minimization: the bot shouldn't be able to see other students' records at all |
| 5. Socratic / academic-integrity bypass | Phase 1 enforced Socratic mode | Phase 2 ingress; Phase 3 `socratic_bypass` intent | Policy vs helpfulness trade-off; no filter can fully decide "help vs cheat" |
| 6. Robotics override / key exfiltration | Phase 3 `quadruped_override` block | Phase 2 ingress on override commands and egress on the root key | Physical-world actions need out-of-band confirmation, not chat text |

**Tier expectations (live model):** *vulnerable* gives up secrets to a direct question; *basic* falls to simple persona or authority tricks; *hardened* usually resists direct attempts; *paranoid* refuses nearly everything and may over-refuse benign questions. A small local model is not deterministic, so expect variation between runs.

---

## 3. What the benchmark can and can't teach

Phase 2 rules are **case-insensitive substring matches**: no regex, no wildcards, no decoding. That is a feature of the lab:

- **Visible suite (27 tests):** 15 ingress attacks + 6 benign + 4 egress leaks + 2 benign replies. A student can reach 100% by copying the test phrases.
- **Held-out suite (26 tests):** the same ideas reworded, encoded, translated or role-played, plus harmless questions that use "scary" words. Rules written as exact phrases catch almost none of it.
- Some held-out techniques are **not catchable by any substring list** (encodings, character spacing). The honest answer is *"static lists have a ceiling; that's why layers exist"*: model hardening and the Phase 3 classifier cover what lists can't. Don't mark students down for failing those; look for whether they *explain* the ceiling.

### Expected auto-scores (Parts 2 + 3, max 55)

| Student rules | Visible | Held-out attacks | Auto points |
| :--- | :--- | :--- | :--- |
| Unedited preset (blank / scaffolded / calibrated) | varies | 0% | **0** (flagged as unedited) |
| Calibrated + a few copied phrases | 100% | ~0% | ~37 (Part 2 ≈ 17.5, Part 3 ≈ 20) |
| Idea-level rules, no over-blocking | 100% | >80% | up to **55** |
| Blocks "exam" / "ferpa" / "dr. miller" outright | 100% | high | Part 3 drops (held-out benign questions use those words) |

---

## 4. Grading the instructor-graded parts (45 pts)

Suggested breakdown. The rubric defines the totals; the sub-scores are a recommendation.

**Part 1: Red Team Documentation (25)**
- 10: ≥4 of 5 missions attempted against the vulnerable tier, with the exact prompt and the model's actual output pasted.
- 8: Correct analysis of *why* it worked or failed (control vs data plane, trust in asserted identity).
- 7: Comparison with `hardened_bot`: what changed and what still worked.
- Red flags: payloads with no outputs; screenshots only; every mission "worked" on the paranoid tier; copied text from the guides.

**Part 4: Defense Brief (20), 4 pts per question** (see the [sentence starters](sentence_starter_template.md))

| Q | Full credit includes | Weak answer |
| :--- | :--- | :--- |
| 1 Attack & technique | Names mission, technique and the target behavior | "I tried to hack it" |
| 2 Baseline vs hardened | Specific behavioral difference *and* one remaining weakness | "Hardened is better" |
| 3 Gateway mechanism | Names the stage (ingress/egress/Phase 3) and the exact rule that fired or missed | Doesn't say which layer |
| 4 Why layers | Explains that prompts alone can't enforce policy; independent controls fail independently | Restates the question |
| 5 Trade-offs & residual risk | A real false-positive example from their own testing and a concrete next control | Generic "AI is risky" |

---

## 5. Verifying submissions

1. Ask for the **`.md` file**, not pasted text (Canvas text boxes alter formatting and break signatures).
2. `REPORT_SECRET=<your secret> python lab/scripts/verify_report.py submissions/*.md` → `VALID` means unchanged since export. `UNSIGNED` means it came from a machine without your secret, so treat it as practice work.
3. Read the **Rule Provenance** line: *"N added / M removed vs calibrated"*. Small numbers with a high score is the memorizer pattern.
4. **Arena stats are self-reported** by the browser; don't grade on them alone.
5. The **rules fingerprint** lets you spot two students submitting identical rules.

---

## 6. Common student mistakes

| Mistake | Symptom | Coaching |
| :--- | :--- | :--- |
| Writing regex in the lists | Rules never match (`.*`, `\b` are literal) | Entries are plain case-insensitive substrings |
| Adding Python (imports, functions, variables) | Save rejected: "only … lists are allowed" | The file is data only; keep the three lists |
| Blocking one broad word ("exam", "record", "key") | Benign tests fail; Part 3 drops | Block the *intent phrase*, not the topic word |
| Hundreds of near-duplicate phrases | High visible, low held-out | Ask what *idea* each phrase represents |
| Only editing ingress | Leaks still reach users | Egress lists catch what slipped through |
| Putting the real secret value in `EGRESS_SECRETS` only | Reworded or reformatted leaks pass | Pair with pattern phrases; discuss the limit of exact matching |
| Expecting presets to reset the benchmark mid-class | Scores "change" after a preset button | Presets overwrite their rules file; re-run the benchmark |

---

## 7. Reading the pipeline trace (for live demos)

| Badge | Meaning |
| :--- | :--- |
| `INTERCEPTED 🛡️` / `BLOCKED ⛔` | Stopped before the model (Phase 2 or Phase 3 ingress) |
| `LEAK CAUGHT 🔒` | Model replied, egress check (Phase 2 or 3) caught a secret |
| `BREACHED 🚨` | A protected secret reached the user: the attack won |
| `ALLOWED 🔓` | Passed everything and nothing sensitive leaked |
| `FALLBACK ⚠️` / `SIMULATED ⚠️` | Selected model wasn't the one that answered; run `build_models.py` / check Ollama |
| Phase 3 labeled "Local Policy Evaluator" | OPA container not running; same `rules.json` rules apply |

**Known behaviors to expect, and use:**
- The local classifier model sometimes **flags harmless questions** (e.g. as authority spoofing). That's a live false-positive example for the usability discussion.
- Responses take roughly 10–25 s on a laptop; the offline simulator is instant.
- Phase 3 `rules.json` can be too strict or too loose: confidence thresholds 0.8 allow / 0.55 clarify are good starting values to let students tune.

---

## 8. Suggested 10-minute lecture demo

(`set_tier.py` overwrites `filter_rules.py`; finish with `calibrated` to leave it in the reference state.)

1. `python lab/scripts/set_tier.py blank` → run the benchmark: everything gets through (attack catch 0%).
2. `… scaffolded` → partial; ask the class what's missing.
3. `… calibrated` → visible 100%. Pause: *"Are we safe?"*
4. Show the **held-out** panel: 0% on rewordings. Discuss why a list can't win.
5. Open the booth (stage 3) or a Phase 3 run and show which layer catches what.

---

## 9. Model answers to the discussion questions

1. **The Ingress Delusion.** A substring list sees only the characters it was given; encodings, other languages and rewordings carry the same intent in different characters. Phase 3 classifies *meaning*, so it can catch intent the list never saw, but it is itself a probabilistic model that can be wrong in both directions. Neither replaces designing the system so the secret isn't reachable.
2. **Defense-in-Depth.** Prompts and ingress filters are attempts to prevent; egress DLP is the last chance to stop impact when prevention fails. Layers fail independently, and egress protects against attacks no one anticipated.
3. **The Socratic Dilemma.** "Helping learn" vs "doing the work" depends on context the bot can't verify (course policy, assignment, intent). A model can enforce a *style* (hints, questions) but not the *boundary* reliably; policy must be explicit and some judgment stays with humans.
