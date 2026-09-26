from pathlib import Path

import pytest

from taintgate import Policy

CODING = Path(__file__).parent.parent / "examples" / "coding_agent.yaml"
MCP = Path(__file__).parent.parent / "examples" / "mcp_server.yaml"


def action(policy, tool, args, session=None):
    return policy.check(tool, args, session).action


@pytest.fixture
def coding_policy():
    return Policy.from_yaml(CODING)


@pytest.fixture
def mcp_policy():
    return Policy.from_yaml(MCP)


def test_example_policies_load(coding_policy, mcp_policy):
    assert coding_policy.default == "ask"
    assert mcp_policy.default == "deny"


def test_coding_agent_workspace_and_secrets(coding_policy):
    assert action(coding_policy, "read_file", {"path": "/workspace/src/main.py"}) == "allow"
    assert action(coding_policy, "write_file", {"path": "/workspace/src/main.py"}) == "allow"
    assert action(coding_policy, "write_file", {"path": "/etc/passwd"}) == "deny"
    assert action(coding_policy, "read_file", {"path": "/workspace/.ssh/id_rsa"}) == "deny"


def test_coding_agent_shell_and_ssrf(coding_policy):
    assert action(coding_policy, "bash", {"command": "pytest tests/"}) == "allow"
    assert action(coding_policy, "bash", {"command": "rm -rf /"}) == "deny"
    assert action(coding_policy, "web_fetch", {"url": "http://169.254.169.254/"}) == "deny"
    assert action(coding_policy, "web_fetch", {"url": "https://pypi.org/simple/taintgate"}) == "allow"


def test_mcp_server_fails_closed(mcp_policy):
    assert action(mcp_policy, "unknown_tool", {}) == "deny"
    assert action(mcp_policy, "read_file", {"path": "/workspace/README.md"}) == "allow"
    assert action(mcp_policy, "fetch", {"url": "http://127.0.0.1:8080/"}) == "deny"
    assert action(mcp_policy, "run_command", {"command": "ls /workspace"}) == "allow"
    assert action(mcp_policy, "run_command", {"command": "rm -rf /"}) == "deny"
