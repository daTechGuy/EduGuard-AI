"""
EduGuard-AI: Blue Team Scaffolded Rules (Intermediate Tier)
===========================================================
This preset gives students a structured starting point for protecting Oakridge University bots.
Uncomment, tune, and expand these lists to balance security against false positives.
"""

# INGRESS: block malicious attack patterns before reaching the LLM
INGRESS_BLACKLIST = [
    # Cat 1: Direct Injection
    "ignore all previous",
    "system prompt",
    # "disregard all",
    # "reveal instructions",

    # Cat 2: Authority Spoofing
    "i am dr. miller",
    # "as lead instructor",
    # "as dean of academic affairs",

    # Cat 3: Indirect Prompt Injection
    "[instructor note]",
    # "award 100 points",
    # "grading override",

    # Cat 5: Socratic Tutoring Bypass
    # "give me the exact answer to q4",
    # "disable socratic",

    # Unitree Quadruped Cyber Dog Ingress Overrides
    # "i am dr. chen",
    # "override quadruped",
    # "/override_quadruped_patrol",
    # "disarm cyberdog",
]

# EGRESS: exact confidential strings that must be caught if the LLM leaks them
EGRESS_SECRETS = [
    # TA Bot Secrets:
    # "CAMPUS-TA-SAGE-01",
    # "EXAM-KEY-CS101-FALL26-Q4-RSA",
    # "RUBRIC-WEIGHT-EXAM1-35PCT",
    # "TA-AUTH-SAGE-7731",
    # "/override_socratic_mode",

    # GraderBot Secrets:
    # "CANVAS-API-KEY-PROD-9912",
    # "LMS-GRADE-OVERRIDE-A_PLUS",
    # "gradebook.canvas.campus.internal",

    # Registrar Secrets:
    # "SIS-REGISTRAR-CORE-01",
    # "REGISTRAR-FERPA-TOKEN-0091",
    # "SID-88391: GPA 1.82 - Academic Suspension",

    # Unitree Quadruped Sentry Secrets:
    # "UNITREE-GO2-CYBERDOG-MK4",
    # "UNITREE-GO2-ROOT-KEY-9941",
    # "CAMPUS-GRID-ZONE4-RESTRICTED",
    # "/override_quadruped_patrol",
    # "K9-CYBERDOG-DISARM-SIG-882",
]

# EGRESS PATTERNS: suspicious heuristic phrases that indicate data leakage or role collapse
EGRESS_PATTERNS = [
    "exam question 4 answer key",
    # "academic suspension",
    # "ta auth token",
    # "canvas api key",
    # "unitree root key",
    # "lidar patrol grid",
    # "disarm signature",
]