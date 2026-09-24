"""taintgate: a policy gate for AI agent tool calls, with provenance tracking."""

from .policy import Decision, Policy, PolicyError, Rule
from .session import Session, ToolCallBlocked

__all__ = ["Decision", "Policy", "PolicyError", "Rule", "Session", "ToolCallBlocked"]
__version__ = "0.1.0"
