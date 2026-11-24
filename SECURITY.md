# Security Policy

## Scope

`mcp-security-gateway` provides deterministic, zero-dependency policy enforcement in front of untrusted Model Context Protocol (MCP) stdio servers. It is designed to complement—not replace—OS-level isolation (non-root containers, `no-new-privileges`, read-only rootfs, network egress restrictions).

## Reporting a Vulnerability

If you discover a policy bypass, path-jail escape, or audit-chain weakness:

- Email: `alexey.zhuykov@gmail.com` (Subject: `[SECURITY] mcp-security-gateway`)
- Please include a minimal reproduction payload and expected vs actual decision.
- Do not open public issues for unpatched security bypasses.
