"""taintgate: a policy gate for AI agent tool calls, with provenance tracking."""

from .policy import Decision, Policy, PolicyError, Rule, args_digest
from .session import Session, ToolCallBlocked

__all__ = ["Decision", "Policy", "PolicyError", "Rule", "Session", "ToolCallBlocked", "args_digest"]
__version__ = "0.1.0"
