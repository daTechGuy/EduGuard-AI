"""
Local Phase 3 Policy Evaluator (used when the OPA engine is not running)
=======================================================================
A line-for-line Python port of policies/gateway.rego that reads the same
student-editable policies/rules.json. The native Windows/Mac setups don't
run OPA, so without this, edits to rules.json would silently do nothing.

Keep this in sync with gateway.rego. Decision chain (first match wins):
  ingress: blacklist -> high-risk flags -> context violations -> clarify
  egress:  secrets -> patterns
  default: allow
"""

import json


def load_policy(rules_path):
    """Returns (policy dict, error message or None)."""
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            policy = json.load(f).get("policy")
        if not isinstance(policy, dict):
            return None, "rules.json has no 'policy' object"
        return policy, None
    except (OSError, ValueError) as e:
        return None, f"rules.json unreadable: {e}"


def _defined(value):
    # Rego treats only `false` and undefined as falsy; "" and 0 are truthy.
    return value is not None and value is not False


def evaluate(policy, stage, prompt_text="", response_text="", context=None):
    """Mirror of `data.gateway.decision`. Pass context=None when no
    classifier output is available; context rules are then skipped
    (Rego's `has_context` is false)."""
    p = policy
    ctx = context or {}
    has_context = _defined(ctx.get("domain")) and _defined(ctx.get("intent"))
    domain, intent = ctx.get("domain"), ctx.get("intent")

    if stage == "ingress":
        prompt_l = (prompt_text or "").lower()
        ingress = [ph for ph in p.get("ingress_blacklist", []) if ph.lower() in prompt_l]
        if ingress:
            return _block("block_ingress", "ingress blacklist match", ingress)

        if has_context:
            risky = {f.lower() for f in p.get("high_risk_flags", [])}
            high = [f for f in ctx.get("risk_flags", []) or [] if f.lower() in risky]
            if high:
                return _block("block_ingress", "classifier flagged high risk", high)

            reason = _context_block_reason(p, domain, intent, ctx.get("confidence"))
            if reason:
                return _block("block_ingress", reason, ["context_policy"])

            conf = ctx.get("confidence")
            clarify, allow = p.get("confidence_threshold_clarify"), p.get("confidence_threshold_allow")
            if conf is not None and clarify is not None and allow is not None and clarify <= conf < allow:
                return _block("require_clarification",
                              f"classifier confidence {conf:.2f} requires clarification", ["context_threshold"])

    elif stage == "egress":
        resp_l = (response_text or "").lower()
        secrets = [s for s in p.get("egress_secrets", []) if s.lower() in resp_l]
        if secrets:
            return _block("block_egress", "egress secret match", secrets)
        patterns = [s for s in p.get("egress_patterns", []) if s.lower() in resp_l]
        if patterns:
            return _block("block_egress", "egress pattern match", patterns)

    return {"allow": True, "action": "allow", "reason": "no policy match", "matched": []}


def _context_block_reason(p, domain, intent, confidence):
    if domain not in p.get("allowed_domains", []):
        return f"context domain '{domain}' is out of scope"
    if intent in p.get("blocked_intents", []):
        return f"context intent '{intent}' is blocked"
    if intent not in (p.get("allowed_intents") or {}).get(domain, []):
        return f"intent '{intent}' is not allowed for domain '{domain}'"
    clarify = p.get("confidence_threshold_clarify")
    if confidence is not None and clarify is not None and confidence < clarify:
        return f"classifier confidence {confidence:.2f} below block threshold {clarify:.2f}"
    return None


def _block(action, reason, matched):
    return {"allow": False, "action": action, "reason": reason, "matched": matched}
