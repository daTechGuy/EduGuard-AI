# EduGuard-AI: Red Team / Blue Team Defense Brief - Sentence Starter Template

Use these sentence starters to draft your academic defense brief. Replace bracketed text with your own evidence and analysis from lab testing.

## 1) Attack Attempt & Prompt Technique

- The attack mission I attempted was [Mission 1: Exam Key Leak / Mission 2: Authority Spoofing / Mission 3: Indirect Homework Injection / Mission 4: FERPA Probe / Mission 5: Socratic Bypass].
- The specific prompt technique I used was [direct injection / roleplay / authority claim / embedded comment / obfuscation].
- My payload attempted to make the assistant [target behavior, e.g. reveal the RSA answer key / change a homework grade / leak GPA], by phrasing the request as [exact strategy or wording].
- The primary indicator that this input was adversarial was [indicator, e.g. claiming instructor identity without credentials / embedding override markers in assignment text].

## 2) Baseline vs Hardened Prompt Behavior

- In `vulnerable_bot`, the assistant responded by [describe model behavior], demonstrating that it [flaw, e.g. trusted user-asserted authority without authentication].
- In `hardened_bot`, the assistant responded by [describe model behavior], showing [improvement or residual vulnerability].
- Comparing both outputs, prompt hardening successfully defended against [specific technique], but remained vulnerable when [alternative attack phrasing or evasion].

## 3) Gateway Filter Mechanism (Caught or Missed)

- The gateway [blocked / allowed] this request at the [ingress / egress / OPA policy] stage.
- The rule or pattern involved was [rule string or secret], which matched [specific payload text].
- If the attack bypassed the filter, it succeeded because [evasion tactic, e.g. synonym substitution / semantic paraphrasing / indirect document context], which was not present in `filter_rules.py`.

## 4) Why Layered Gateway Defense Is Necessary Beyond System Prompts

- System prompts alone were insufficient to protect [Sage / GraderBot / Morgan] because [fundamental LLM limitation: control-plane vs data-plane confusion].
- The gateway adds an independent control layer by [mechanism: pre-model ingress blocking / post-model DLP egress filtering / policy engine evaluation].
- This defense-in-depth approach ensures that even if an attacker tricks the model's reasoning, [sensitive asset, e.g. exam key / FERPA data] cannot be exfiltrated back to the client.

## 5) Usability vs Security Trade-offs & Residual Risk

- To avoid false positives on legitimate student inquiries, I had to ensure that [legitimate phrase, e.g. 'Dr. Simon\'s office hours' or 'exam format questions'] was not blocked by overly broad triggers like [overly broad rule].
- Residual risk remains in cases where an adversary uses [unforeseen bypass, e.g. foreign language translation / base64 encoding / subtle multi-turn social engineering].
- To further strengthen defense against this residual risk, the next control I would implement is [proposed control, e.g. classifier embeddings / cryptographic token verification / OPA role-based authentication].