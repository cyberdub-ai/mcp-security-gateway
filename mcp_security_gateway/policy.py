"""Declarative JSON policy model for mcp-security-gateway."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

DEFAULT_POISON_PATTERNS: list[str] = [
    r"<\s*(important|system|instruction)\b",
    r"(ignore|disregard|override)\s+(all\s+)?(previous|prior|above)",
    r"(игнорируй|забудь)\s+(все\s+)?(предыдущ|прошл)",
    r"(do\s+not\s+tell|silently|exfiltrat|не\s+сообща)",
    r"(\.ssh/id_rsa|api_token|\.env|/etc/shadow|/etc/passwd)",
]


@dataclass(frozen=True)
class ToolRule:
    name: str
    mode: str = "read_only"  # "read_only" | "mutating"
    allowed_args: frozenset[str] = field(default_factory=frozenset)
    requires_approval: bool = False
    untrusted_output: bool = False
    path_jail_arg: str | None = None
    filename_pattern: str = r"^[a-zA-Z0-9._-]{1,64}$"
    pinned_sha256: str | None = None
    max_calls_per_minute: int = 60


@dataclass
class GatewayPolicy:
    tools: dict[str, ToolRule]
    jail_root: str
    approval_env_var: str = "MCP_APPROVAL_TOKEN"
    expected_approval_token: str = "APPROVED-BY-OPERATOR"
    poison_patterns: list[re.Pattern[str]] = field(default_factory=list)
    default_deny_unlisted: bool = True

    def __post_init__(self) -> None:
        self.jail_root = os.path.realpath(self.jail_root)
        if not self.poison_patterns:
            self.poison_patterns = [re.compile(p, re.I) for p in DEFAULT_POISON_PATTERNS]


def load_policy(path: str) -> GatewayPolicy:
    with open(path, "r", encoding="utf-8") as f:
        raw: dict[str, Any] = json.load(f)

    base_dir = os.path.dirname(os.path.abspath(path))
    jail_root = raw.get("jail_root", ".")
    if not os.path.isabs(jail_root):
        jail_root = os.path.join(base_dir, jail_root)

    tools: dict[str, ToolRule] = {}
    for name, cfg in raw.get("tools", {}).items():
        tools[name] = ToolRule(
            name=name,
            mode=cfg.get("mode", "read_only"),
            allowed_args=frozenset(cfg.get("allowed_args", [])),
            requires_approval=bool(cfg.get("requires_approval", cfg.get("mode") == "mutating")),
            untrusted_output=bool(cfg.get("untrusted_output", False)),
            path_jail_arg=cfg.get("path_jail_arg"),
            filename_pattern=cfg.get("filename_pattern", r"^[a-zA-Z0-9._-]{1,64}$"),
            pinned_sha256=cfg.get("pinned_sha256"),
            max_calls_per_minute=int(cfg.get("max_calls_per_minute", 60)),
        )

    patterns = [re.compile(p, re.I) for p in raw.get("poison_patterns", DEFAULT_POISON_PATTERNS)]
    return GatewayPolicy(
        tools=tools,
        jail_root=jail_root,
        approval_env_var=raw.get("approval_env_var", "MCP_APPROVAL_TOKEN"),
        expected_approval_token=raw.get("expected_approval_token", "APPROVED-BY-OPERATOR"),
        poison_patterns=patterns,
        default_deny_unlisted=bool(raw.get("default_deny_unlisted", True)),
    )

