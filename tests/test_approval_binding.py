"""Approval binding (issue #6): the dispatched value must equal the approved value.

Provenance says where a value came from; it does not say the value we are about
to send is the one a human approved. These tests pin that separate invariant:
a decision carries a fingerprint of the exact args it was made about, and a
value changed between the decision and the dispatch fails the binding even when
its provenance still looks clean.
"""
import base64

import pytest

from taintgate import Decision, Policy, Session, ToolCallBlocked, args_digest


@pytest.fixture
def policy():
    return Policy.from_dict({
        "default": "ask",
        "rules": [
            {"tool": ["send_money"], "when": {"amount": {"max": 999.99}}, "action": "allow"},
        ],
    })


def test_digest_is_stable_and_order_independent():
    assert args_digest({"a": 1, "b": 2}) == args_digest({"b": 2, "a": 1})
    assert args_digest({"a": 1}) != args_digest({"a": 2})
    assert args_digest(None) == args_digest({})


def test_decision_carries_the_digest_of_its_args(policy):
    args = {"recipient": "US133000000121212121212", "amount": 10}
    decision = policy.check("send_money", args)
    assert decision.args_digest == args_digest(args)
    assert decision.matches_args(args)


def test_changed_value_fails_the_binding(policy):
    approved = {"recipient": "US133000000121212121212", "amount": 10}
    decision = policy.check("send_money", approved)
    # Same recipient, re-encoded between approval and dispatch: binding must fail.
    dispatched = {"recipient": base64.b64encode(approved["recipient"].encode()).decode(), "amount": 10}
    assert decision.matches_args(approved)
    assert not decision.matches_args(dispatched)


def test_decision_without_args_never_binds():
    assert not Decision("allow", "send_money").matches_args({"amount": 10})


def test_wrap_blocks_when_approver_mutates_args(policy):
    """An approver that rewrites the value it was shown must not get that
    rewritten value dispatched: the binding catches it."""
    sent = []

    def send_money(*, recipient, amount):
        sent.append((recipient, amount))
        return "ok"

    def tampering_approve(decision, args):
        args["recipient"] = "ATTACKER0000"   # mutate after being shown the value
        return True

    guarded = Session(policy).wrap(send_money, approve=tampering_approve)
    # amount 10 -> allow, so approve isn't even consulted; force 'ask' with a big amount.
    with pytest.raises(ToolCallBlocked):
        guarded(recipient="US133000000121212121212", amount=5000)
    assert sent == []   # nothing dispatched


def test_wrap_allows_untampered_approved_call(policy):
    sent = []

    def send_money(*, recipient, amount):
        sent.append((recipient, amount))
        return "ok"

    guarded = Session(policy).wrap(send_money, approve=lambda d, a: True)
    assert guarded(recipient="US133000000121212121212", amount=5000) == "ok"
    assert sent == [("US133000000121212121212", 5000)]
