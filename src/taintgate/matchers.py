"""
Argument matchers used in a rule's `when:` block.

Each matcher takes the argument's value, the matcher's configured operand,
and the session (for provenance checks), and returns True if it matches.
"""

import fnmatch
import ipaddress
import posixpath
import re
import socket
from urllib.parse import urlparse

# Values shorter than this are too generic to trace back to a source
# (an amount like "5" appears in almost any text).
MIN_TRACE_LENGTH = 4


def _as_list(operand):
    return operand if isinstance(operand, list) else [operand]


def _normpath(value):
    """Expand ~ and collapse ../ so '/work/../home/.ssh' can't dodge a glob."""
    path = posixpath.expanduser(str(value))
    return posixpath.normpath(path) if path else path


def _host(value):
    text = str(value)
    host = urlparse(text if "://" in text else f"//{text}").hostname
    return (host or "").lower().rstrip(".")


def _host_matches(host, domains):
    return any(host == d or host.endswith("." + d) for d in (d.lower() for d in domains))


def _is_private_host(host):
    """True for loopback, private, link-local (e.g. cloud metadata) and localhost."""
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost") or host == "metadata.google.internal":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:   # a few common non-dotted forms, e.g. 2852039166 == 169.254.169.254
            ip = ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(host)))
        except (OSError, ValueError):
            return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _squash(text):
    """Lowercase and drop spaces/punctuation, so 'US13 3000-0001' == 'us1330000001'."""
    return re.sub(r"[\W_]+", "", str(text).lower())


def _untrusted(value, expected, session):
    """Did this value come from untrusted tool output rather than the user?"""
    text = _squash(value)
    if len(text) < MIN_TRACE_LENGTH or session is None:
        return not expected
    seen_untrusted = any(text in _squash(chunk) for chunk in session.untrusted_text)
    said_by_user = any(text in _squash(chunk) for chunk in session.trusted_text)
    return (seen_untrusted and not said_by_user) == expected


def _from_user(value, expected, session):
    """Did the user type this value? Stricter than `untrusted: false`, which
    also passes values that appear nowhere (e.g. made up by the model)."""
    text = _squash(value)
    if len(text) < MIN_TRACE_LENGTH or session is None:
        return not expected
    return any(text in _squash(chunk) for chunk in session.trusted_text) == expected


MATCHERS = {
    "equals":      lambda v, op, s: v == op,
    "not_equals":  lambda v, op, s: v != op,
    "in":          lambda v, op, s: v in _as_list(op),
    "not_in":      lambda v, op, s: v not in _as_list(op),
    "contains":    lambda v, op, s: any(str(o).lower() in str(v).lower() for o in _as_list(op)),
    "glob":        lambda v, op, s: any(fnmatch.fnmatch(_normpath(v), _normpath(p)) for p in _as_list(op)),
    "not_glob":    lambda v, op, s: not any(fnmatch.fnmatch(_normpath(v), _normpath(p)) for p in _as_list(op)),
    "regex":       lambda v, op, s: any(re.search(p, str(v)) for p in _as_list(op)),
    "not_regex":   lambda v, op, s: not any(re.search(p, str(v)) for p in _as_list(op)),
    "min":         lambda v, op, s: _number(v) is not None and _number(v) >= op,
    "max":         lambda v, op, s: _number(v) is not None and _number(v) <= op,
    "host_in":     lambda v, op, s: _host_matches(_host(v), _as_list(op)),
    "host_not_in": lambda v, op, s: bool(_host(v)) and not _host_matches(_host(v), _as_list(op)),
    "private_host": lambda v, op, s: _is_private_host(_host(v)) == bool(op),
    "untrusted":   lambda v, op, s: _untrusted(v, bool(op), s),
    "from_user":   lambda v, op, s: _from_user(v, bool(op), s),
}


def check_matchers(value, spec, session):
    """All matchers in `spec` must match `value` (AND)."""
    return all(MATCHERS[name](value, operand, session) for name, operand in spec.items())
