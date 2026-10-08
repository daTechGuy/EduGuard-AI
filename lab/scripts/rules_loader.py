"""
Data-only loader for Phase 2 filter_rules.py
============================================
filter_rules.py looks like Python, but it is never imported or executed.
It is parsed, and only these three list assignments are accepted:

    INGRESS_BLACKLIST = ["...", ...]
    EGRESS_SECRETS = ["...", ...]
    EGRESS_PATTERNS = ["...", ...]

Comments and docstrings are fine. Anything else (imports, function calls,
defs, other variables) is rejected. The Defense Studio can save this file
from the browser, so executing it would let anyone who reaches the web
page run code on the host.
"""

import ast

RULE_NAMES = ("INGRESS_BLACKLIST", "EGRESS_SECRETS", "EGRESS_PATTERNS")


class RulesError(ValueError):
    pass


def parse_rules(source, filename="filter_rules.py"):
    """Returns {name: [str, ...]} for the three rule lists (missing -> [])."""
    try:
        tree = ast.parse(source, filename)
    except SyntaxError as e:
        raise RulesError(f"Python SyntaxError on line {e.lineno}: {e.msg}") from None
    except (ValueError, MemoryError, RecursionError) as e:
        raise RulesError(f"Could not parse filter_rules.py: {type(e).__name__}") from None

    rules = {name: [] for name in RULE_NAMES}
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue  # docstring / bare string
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            raise RulesError(_only_lists_msg(node))
        if not (isinstance(target, ast.Name) and target.id in RULE_NAMES):
            raise RulesError(_only_lists_msg(node))
        try:
            items = ast.literal_eval(value)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            raise RulesError(f"Line {node.lineno}: {target.id} must be a plain list of strings "
                             "(no variables, function calls or expressions).") from None
        if not isinstance(items, (list, tuple)) or not all(isinstance(i, str) for i in items):
            raise RulesError(f"Line {node.lineno}: {target.id} must be a list of strings.")
        rules[target.id] = list(items)
    return rules


def load_rules_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return parse_rules(f.read(), path)


def _only_lists_msg(node):
    return (f"Line {node.lineno}: only INGRESS_BLACKLIST / EGRESS_SECRETS / EGRESS_PATTERNS "
            f"= [\"...\"] lists are allowed in filter_rules.py (found {type(node).__name__}).")
