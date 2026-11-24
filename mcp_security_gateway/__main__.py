"""CLI entry point: python -m mcp_security_gateway --policy policy.json --audit audit.jsonl -- <upstream cmd>"""

from __future__ import annotations

import argparse
import sys

from .audit import HashChainedAuditLogger
from .gateway import MCPSecurityGateway
from .policy import load_policy
from .proxy import StdioMCPProxy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-security-gateway",
        description="Zero-Trust Security Policy Proxy for MCP servers (JSON-RPC 2.0 over stdio).",
    )
    parser.add_argument("--policy", required=True, help="Path to declarative JSON policy file")
    parser.add_argument("--audit", default="audit.jsonl", help="Path to hash-chained JSONL audit log")
    parser.add_argument("--verify-audit", action="store_true", help="Verify audit log chain and exit")
    parser.add_argument("upstream", nargs=argparse.REMAINDER, help="Upstream MCP server command after '--'")

    args = parser.parse_args(argv)

    if args.verify_audit:
        ok, count, msg = HashChainedAuditLogger.verify_chain(args.audit)
        print(f"audit_verify: ok={ok} entries={count} status={msg}")
        return 0 if ok else 2

    cmd = list(args.upstream)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("Provide upstream MCP command after '--', e.g.: -- python server.py")

    policy = load_policy(args.policy)
    logger = HashChainedAuditLogger(args.audit)
    gw = MCPSecurityGateway(policy, logger)
    proxy = StdioMCPProxy(gw, cmd)
    proxy.serve_stdio()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
