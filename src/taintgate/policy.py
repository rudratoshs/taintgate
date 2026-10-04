"""
Policies: an ordered list of rules plus a default action.

Every rule that matches a call contributes its action, and the strictest one
wins (deny > ask > allow). Rule order therefore can't accidentally open a
hole: an `allow` listed first never overrides a later `deny`.
"""

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field

from .matchers import MATCHERS, check_matchers

ACTIONS = ("allow", "ask", "deny")
STRICTNESS = {action: rank for rank, action in enumerate(ACTIONS)}


def args_digest(args):
    """A stable fingerprint of a call's arguments.

    Provenance says where a value came from; this says *which exact value* a
    decision was made about. Two calls fingerprint the same only if their args
    are equal after a canonical JSON serialisation (keys sorted, non-JSON
    values via str). It is what ties an approval to the value approved: a
    recipient re-derived, re-fetched or re-encoded between the check and the
    dispatch produces a different digest, so the binding fails even when the
    new value's provenance still looks clean.
    """
    blob = json.dumps(args or {}, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


class PolicyError(ValueError):
    """The policy file is malformed. Raised at load time, never mid-run."""


@dataclass
class Decision:
    action: str                                  # "allow" | "ask" | "deny"
    tool: str
    reasons: list = field(default_factory=list)  # one per matched rule
    args_digest: str = None                      # fingerprint of the args decided on

    @property
    def allowed(self):
        return self.action == "allow"

    def matches_args(self, args):
        """True if `args` is byte-identical (after canonical JSON) to the args
        this decision was made about. Use before dispatching an approved call:
        a value changed since the decision — re-derived, re-fetched, re-encoded
        — will not match, even if its provenance still looks clean. Returns
        False if this decision carries no digest (made without args)."""
        return self.args_digest is not None and self.args_digest == args_digest(args)

    def __str__(self):
        why = "; ".join(self.reasons) or "default policy"
        return f"{self.action.upper()} {self.tool}: {why}"


@dataclass
class Rule:
    tool: list                  # tool-name globs
    action: str
    when: dict = None           # {arg name or "*": {matcher: operand}}
    tainted: bool = None        # only match when the session's taint equals this
    reason: str = ""

    def matches(self, tool, args, session):
        if not any(fnmatch.fnmatchcase(tool, pattern) for pattern in self.tool):
            return False
        if self.tainted is not None and (session is not None and session.tainted) != self.tainted:
            return False
        for arg, spec in (self.when or {}).items():
            if arg == "*":
                if not any(check_matchers(v, spec, session) for v in _leaf_values(args)):
                    return False
            elif arg not in args or not check_matchers(args[arg], spec, session):
                return False
        return True

    def describe(self):
        return self.reason or f"rule '{self.action}' on {', '.join(self.tool)}"


def _leaf_values(value):
    """Every scalar inside nested args, so '*' rules can't be dodged by nesting."""
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaf_values(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _leaf_values(v)
    else:
        yield value


class Policy:
    def __init__(self, rules, default="ask", untrusted_sources=("*",)):
        if default not in ACTIONS:
            raise PolicyError(f"default must be one of {ACTIONS}, got {default!r}")
        self.rules = rules
        self.default = default
        self.untrusted_sources = list(untrusted_sources)

    # --- loading -----------------------------------------------------------

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise PolicyError("policy must be a mapping")
        unknown = set(data) - {"version", "default", "untrusted_sources", "rules"}
        if unknown:
            raise PolicyError(f"unknown top-level keys: {sorted(unknown)}")
        rules = [_parse_rule(raw, i) for i, raw in enumerate(data.get("rules") or [])]
        sources = data.get("untrusted_sources", ["*"])
        return cls(rules, data.get("default", "ask"), _as_list(sources))

    @classmethod
    def from_yaml(cls, path):
        import yaml
        with open(path) as f:
            return cls.from_dict(yaml.safe_load(f) or {})

    # --- evaluation --------------------------------------------------------

    def is_untrusted_source(self, tool):
        return any(fnmatch.fnmatchcase(tool, p) for p in self.untrusted_sources)

    def check(self, tool, args=None, session=None):
        """Decide one tool call. Pass a Session to enable taint/provenance rules."""
        args = args or {}
        digest = args_digest(args)
        matched = [r for r in self.rules if r.matches(tool, args, session)]
        if not matched:
            return Decision(self.default, tool, args_digest=digest)
        action = max((r.action for r in matched), key=STRICTNESS.get)
        reasons = [r.describe() for r in matched if r.action == action]
        return Decision(action, tool, reasons, args_digest=digest)


def _as_list(value):
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _parse_rule(raw, index):
    where = f"rules[{index}]"
    if not isinstance(raw, dict):
        raise PolicyError(f"{where} must be a mapping")
    unknown = set(raw) - {"tool", "action", "when", "tainted", "reason"}
    if unknown:
        raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")
    if "tool" not in raw or raw.get("action") not in ACTIONS:
        raise PolicyError(f"{where}: needs 'tool' and an 'action' in {ACTIONS}")
    when = raw.get("when") or {}
    if not isinstance(when, dict):
        raise PolicyError(f"{where}.when must be a mapping of argument -> matchers")
    for arg, spec in when.items():
        if not isinstance(spec, dict) or not spec:
            raise PolicyError(f"{where}.when.{arg} must be a non-empty mapping of matchers")
        bad = set(spec) - set(MATCHERS)
        if bad:
            raise PolicyError(f"{where}.when.{arg}: unknown matchers {sorted(bad)}; "
                              f"available: {sorted(MATCHERS)}")
    tainted = raw.get("tainted")
    if tainted is not None and not isinstance(tainted, bool):
        raise PolicyError(f"{where}.tainted must be true or false")
    return Rule(_as_list(raw["tool"]), raw["action"], when, tainted, raw.get("reason", ""))
