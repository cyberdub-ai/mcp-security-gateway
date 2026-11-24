"""mcp-security-gateway: Zero-dependency Zero-Trust Security Policy Proxy for MCP (JSON-RPC 2.0 over stdio)."""

__version__ = "0.1.0"

from .audit import HashChainedAuditLogger
from .gateway import MCPSecurityGateway, PolicyDecision
from .policy import GatewayPolicy, ToolRule, load_policy

__all__ = [
    "__version__",
    "GatewayPolicy",
    "HashChainedAuditLogger",
    "MCPSecurityGateway",
    "PolicyDecision",
    "ToolRule",
    "load_policy",
]
