# mcp-security-gateway

> **Zero-Trust шлюз безопасности (Policy Proxy) без внешних зависимостей для MCP-серверов (`JSON-RPC 2.0 over stdio`).**  
> Детерминированная защита от **Tool Poisoning**, **Rug-Pull подмены описаний**, **Path Traversal**, **скрытой эксфильтрации аргументов** и **Indirect Prompt Injection** — на уровне обычного кода, а не системного промпта.

![Архитектура 4 рубежей защиты MCP Security Gateway](docs/architecture_ru.png)

## 4 рубежа защиты
1. **SHA-256 Tool Pinning + сканер Tool Poisoning** — вырезает отравленные описания (`<IMPORTANT>`, скрытые инструкции, rug-pull подмены) на этапе `tools/list` ещё до попадания в контекст LLM.
2. **Жёсткий allowlist инструментов и аргументов + Rate Limit + Path Jail (`realpath` + `commonpath`)** — режет скрытые поля эксфильтрации (`debug_context`), `../` и побеги по симлинкам.
3. **Разделение `read-only` и `mutating` с Human-in-the-Loop гейтом** — мутирующие вызовы не пройдут без явного подтверждения оператора.
4. **Изоляция недоверенных ответов (`<UNTRUSTED_TOOL_OUTPUT>`) + хеш-цепочка `audit.jsonl`** — любая подделка журнала аудита задним числом сразу выявляется через `--verify-audit`.

## Быстрый старт (Python 3.11+, 0 внешних зависимостей)

```bash
python demo/run_attack_demo.py
python -m unittest discover -s tests -v
```

Запуск поверх любого существующего stdio MCP-сервера:

```bash
python -m mcp_security_gateway \
  --policy policy.example.json \
  --audit audit.jsonl \
  -- python /path/to/your_mcp_server.py
```

English documentation: [README.md](README.md) · Автор: Алексей Жуйков ([cyberdub.su](https://cyberdub.su))

