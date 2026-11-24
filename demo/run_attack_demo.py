"""Side-by-side live demo: Vulnerable MCP server vs Protected by mcp-security-gateway."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVER = os.path.join(ROOT, "demo", "vulnerable_mcp_server.py")
POLICY = os.path.join(ROOT, "policy.example.json")


def setup_mock_fs() -> None:
    logs = os.path.join(ROOT, "demo", "mock_fs", "logs")
    secrets = os.path.join(ROOT, "demo", "mock_fs", "secrets")
    os.makedirs(logs, exist_ok=True)
    os.makedirs(secrets, exist_ok=True)
    with open(os.path.join(logs, "app.log"), "w", encoding="utf-8") as f:
        f.write("2026-11-24T10:00:00Z INFO health=ok latency_ms=14\n")
    with open(os.path.join(secrets, "api_token.txt"), "w", encoding="utf-8") as f:
        f.write("DEMO_SECRET_TOKEN_DO_NOT_EXFILTRATE_9999\n")


def run_rpc(cmd: list[str], requests: list[dict]) -> list[dict]:
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        cwd=ROOT,
    )
    assert proc.stdin is not None and proc.stdout is not None
    responses = []
    for req in requests:
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        responses.append(json.loads(proc.stdout.readline()))
    proc.stdin.close()
    proc.wait(timeout=5)
    return responses


def main() -> None:
    setup_mock_fs()
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_log", "arguments": {"filename": "app.log"}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_log", "arguments": {"filename": "../secrets/api_token.txt"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "format_currency", "arguments": {"amount": 100, "currency": "USD", "debug_context": "STOLEN"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "read_ticket", "arguments": {"ticket_id": "1042"}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "restart_service", "arguments": {"service_name": "nginx"}}},
    ]

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        audit_path = tf.name

    print("=== PROTECTED BY mcp-security-gateway ===")
    gw_cmd = [sys.executable, "-m", "mcp_security_gateway", "--policy", POLICY, "--audit", audit_path, "--", sys.executable, SERVER]
    resps = run_rpc(gw_cmd, requests)
    for r in resps:
        print(f"  id={r['id']}: {json.dumps(r, ensure_ascii=False)[:180]}")

    ver = subprocess.run(
        [sys.executable, "-m", "mcp_security_gateway", "--policy", POLICY, "--audit", audit_path, "--verify-audit"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    print("  " + ver.stdout.strip())
    os.unlink(audit_path)


if __name__ == "__main__":
    main()

