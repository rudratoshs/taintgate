"""
Sessions track provenance for one agent run: what the user said (trusted)
and what tools returned (untrusted). Rules use this through `tainted:` and
the `untrusted:` matcher.
"""

import functools
import json

from .policy import Policy


class ToolCallBlocked(PermissionError):
    """Raised by a wrapped tool when the policy denies it (or 'ask' is refused)."""

    def __init__(self, decision):
        super().__init__(str(decision))
        self.decision = decision


class Session:
    def __init__(self, policy: Policy, user_messages=()):
        self.policy = policy
        self.trusted_text = [str(m) for m in user_messages]
        self.untrusted_text = []

    @property
    def tainted(self):
        """True once any untrusted tool output has entered the agent's context."""
        return bool(self.untrusted_text)

    def add_user_message(self, text):
        self.trusted_text.append(str(text))

    def observe(self, tool, output):
        """Record a tool's output. Untrusted sources taint the session."""
        if output is None or not self.policy.is_untrusted_source(tool):
            return
        text = output if isinstance(output, str) else json.dumps(output, default=str)
        self.untrusted_text.append(text)

    def check(self, tool, args=None):
        return self.policy.check(tool, args or {}, session=self)

    def wrap(self, fn, name=None, approve=None):
        """Guard a tool function: check before it runs, observe what it returns.

        `approve(decision, args) -> bool` is called for 'ask' decisions; with
        no approver, 'ask' is treated as deny (fail closed).
        """
        tool = name or fn.__name__

        @functools.wraps(fn)
        def guarded(**args):
            decision = self.check(tool, args)
            if decision.action == "deny" or (
                decision.action == "ask" and not (approve and approve(decision, args))
            ):
                raise ToolCallBlocked(decision)
            result = fn(**args)
            self.observe(tool, result)
            return result

        return guarded
