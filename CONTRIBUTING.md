# Contributing to taintgate

Thanks for wanting to help. taintgate is an early, honest prototype — it works
for a class of attacks and openly fails on others (see the README's caveats). That
makes it a great place to contribute: the gaps are written down, and closing any
of them is a real improvement.

## Good places to start

**Add a matcher.** Matchers are how a policy rule inspects a tool-call argument
(`untrusted`, `from_user`, `host_in`, `private_host`, …). They live in
`src/taintgate/matchers.py` and each is a small function:

```python
# a matcher takes (value, operand, session) and returns True/False
"my_matcher": lambda v, op, s: ...,
```

Add one, add a test in `tests/`, and open a PR.

**Add an example policy.** A well-commented `policy.yaml` for a real agent shape
(a coding agent, a support bot, an MCP server) helps people see how to use this.

**Attack the known limits.** The README lists where provenance breaks:
- a value that's **transformed** before use (string matching loses it)
- a value **laundered** across multiple tools (session-level taint, not value-level)
- distinguishing a **malicious** untrusted value from a **legitimate** one

A failing test that demonstrates one of these clearly is a valuable contribution
on its own — it makes the limitation reproducible.

## Ground rules

- **No LLM in the decision path.** taintgate is deliberately deterministic. If a
  fix needs a model to judge intent, it belongs in a detector, not here.
- **Keep dependencies at zero** (pyyaml only). Part of the value is that this
  runs anywhere with no heavy install.
- **Be honest about limits.** If your change helps one case and breaks another,
  say so in the PR. Documented failure modes are the whole point.

## Running it locally

```bash
pip install -e .
python -m pytest
python examples/banking_demo.py
```

Open an issue if anything's unclear — questions are welcome.
