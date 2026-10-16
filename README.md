# Omisa Document Platform

Omisa Document Platform contains Python components for securely saving, parsing, and reading user documents in an agent gateway.

## Components

- `document-store/` provides explicit, scope-aware durable document storage and metadata tools.
- `history-plugin/` provides bounded message-history and attachment capabilities, with document parsing and cursor-based reads.
- `parser/` extracts bounded text and structured records from common document formats. Its broker and packaging code are designed to isolate parsing from the gateway process.

The history plugin vendors the small parser protocol/schema package it needs so that the integration remains self-contained. The parser package also includes Linux service and sandbox packaging inputs. Review `parser/packaging/DEPLOYMENT.md` before using those inputs in another environment.

## Development

The parser targets Python 3.11 or newer. Its pinned dependencies and test configuration are in `parser/pyproject.toml` and `parser/uv.lock`.

```bash
cd parser
uv sync --extra test
uv run pytest -q
```

The plugin suites are under `history-plugin/tests/` and `document-store/tests/`. They exercise gateway integration through isolated fixtures; they do not configure or start a live agent.

## Security scope

Document contents are untrusted input. The parser uses bounded extraction, opaque references, and a broker boundary; parser libraries alone are not treated as a security boundary. The gateway must provide trusted actor, chat, turn, and attachment context for the capability checks to work. The packages are not a substitute for reviewing the target gateway configuration and host sandbox.

## License

This project is distributed under the Omsk Open License (basic modification, attribution required). See [LICENSE-RU.md](LICENSE-RU.md) for the license terms.
