"""Transparent JSON-RPC 2.0 over stdio security proxy for any MCP server."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import IO, Any

from .gateway import MCPSecurityGateway


class StdioMCPProxy:
    """Wraps an upstream stdio MCP server process and enforces gateway policies."""

    def __init__(self, gateway: MCPSecurityGateway, upstream_cmd: list[str]) -> None:
        self.gateway = gateway
        self.upstream_cmd = upstream_cmd
        self._proc: subprocess.Popen[str] | None = None

    def _start_upstream(self) -> subprocess.Popen[str]:
        if self._proc is None or self._proc.poll() is not None:
            self._proc = subprocess.Popen(
                self.upstream_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=sys.stderr,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        return self._proc

    def _forward(self, request: dict[str, Any]) -> dict[str, Any]:
        proc = self._start_upstream()
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps(request, ensure_ascii=False) + "\n")
        proc.stdin.flush()
        raw = proc.stdout.readline()
        if not raw:
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32001, "message": "Upstream MCP server closed stdout"},
            }
        return json.loads(raw)

    def handle_request(self, req: dict[str, Any]) -> dict[str, Any]:
        req_id = req.get("id")
        method = req.get("method")

        if method == "tools/list":
            upstream_resp = self._forward(req)
            if "result" in upstream_resp and isinstance(upstream_resp["result"], dict):
                tools = upstream_resp["result"].get("tools", [])
                safe_tools, _blocked = self.gateway.inspect_tools_list(tools, request_id=req_id)
                upstream_resp["result"]["tools"] = safe_tools
            return upstream_resp

        if method == "tools/call":
            params = req.get("params") or {}
            tool_name = str(params.get("name", ""))
            args = params.get("arguments") or {}
            approval = params.get("_approval_token")

            decision = self.gateway.validate_call(
                tool_name, args, approval_token=approval, request_id=req_id
            )
            if not decision.allowed:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32010,
                        "message": f"Policy denied ({decision.reason}): {decision.message}",
                    },
                }

            # Strip internal approval field before forwarding upstream
            clean_params = {"name": tool_name, "arguments": args}
            clean_req = {"jsonrpc": "2.0", "id": req_id, "method": "tools/call", "params": clean_params}
            upstream_resp = self._forward(clean_req)
            if "result" in upstream_resp and isinstance(upstream_resp["result"], dict):
                upstream_resp["result"] = self.gateway.sanitize_response(
                    tool_name, upstream_resp["result"], request_id=req_id
                )
            return upstream_resp

        return self._forward(req)

    def serve_stdio(self, stdin: IO[str] = sys.stdin, stdout: IO[str] = sys.stdout) -> None:
        try:
            for raw in stdin:
                line = raw.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError as exc:
                    resp: dict[str, Any] = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": f"Parse error: {exc}"},
                    }
                else:
                    resp = self.handle_request(req)
                stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                stdout.flush()
        finally:
            self.close()

    def close(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()

