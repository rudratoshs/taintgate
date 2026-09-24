"""
taintgate CLI.

    taintgate validate policy.yaml
    taintgate check policy.yaml send_money --args '{"recipient": "US13...", "amount": 100}' \
        --user "Pay my rent" --untrusted "$(cat bill.txt)"

`check` exits 0 for allow, 1 for deny, 2 for ask, so it works in shell hooks.
"""

import argparse
import json
import sys

from .policy import Policy, PolicyError
from .session import Session

EXIT_CODES = {"allow": 0, "deny": 1, "ask": 2}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="taintgate", description=__doc__.split("\n")[1])
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="check a policy file loads cleanly")
    validate.add_argument("policy")

    check = sub.add_parser("check", help="decide one tool call")
    check.add_argument("policy")
    check.add_argument("tool")
    check.add_argument("--args", default="{}", help="tool arguments as JSON")
    check.add_argument("--user", action="append", default=[], help="trusted user message")
    check.add_argument("--untrusted", action="append", default=[],
                       help="untrusted tool output seen earlier in the run")

    opts = parser.parse_args(argv)
    try:
        policy = Policy.from_yaml(opts.policy)
    except (OSError, PolicyError) as e:
        print(f"taintgate: {e}", file=sys.stderr)
        return 3

    if opts.command == "validate":
        print(f"ok: {len(policy.rules)} rules, default={policy.default}")
        return 0

    try:
        args = json.loads(opts.args)
    except json.JSONDecodeError as e:
        print(f"taintgate: --args is not valid JSON: {e}", file=sys.stderr)
        return 3
    session = Session(policy, user_messages=opts.user)
    for text in opts.untrusted:
        session.untrusted_text.append(text)
    decision = session.check(opts.tool, args)
    print(json.dumps({"action": decision.action, "tool": decision.tool,
                      "reasons": decision.reasons}))
    return EXIT_CODES[decision.action]


if __name__ == "__main__":
    sys.exit(main())
