FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin mcpuser
WORKDIR /app

COPY --chown=10001:10001 pyproject.toml policy.example.json ./
COPY --chown=10001:10001 mcp_security_gateway ./mcp_security_gateway
COPY --chown=10001:10001 demo ./demo

RUN pip install --no-cache-dir --no-deps .

USER 10001:10001

ENTRYPOINT ["mcp-security-gateway", "--policy", "/app/policy.example.json", "--audit", "/tmp/audit.jsonl", "--"]
CMD ["python", "/app/demo/vulnerable_mcp_server.py"]

