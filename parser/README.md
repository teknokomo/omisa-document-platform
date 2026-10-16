# Omisa parser

A bounded document extraction package with a one-shot worker, an AF_UNIX/SCM_RIGHTS broker, protocol schemas, and Linux sandbox packaging inputs.

## Development

```bash
uv sync --extra test
uv run pytest -q
```

The parser accepts content-detected text, Markdown, CSV/TSV, JSON, safe XML, RTF, PDF, DOCX, XLSX, PPTX, ODT, ODS, and ODP. It rejects unsupported or unsafe containers and applies size, record, and extraction limits. XLSX formulas are returned as data; they are never evaluated.

`omisa_parser.protocol` validates framed requests, file descriptors, peer credentials, and replay controls. `omisa_parser.service` copies the authorized input into a private job directory, starts a fixed worker, validates bounded JSONL output, and removes job files. The package's integration tests use local fixtures and stubs.

## Packaging

`packaging/` contains socket-activated systemd units, a constrained worker launcher, seccomp policy inputs, root filesystem assembly scripts, and a staging installer. The installer requires a `DESTDIR` and does not enable or start services. The versioned BPF policy artifacts under `packaging/seccomp/out/` are package inputs; rebuild and verify them with the included tooling before changing the policy.

Review `packaging/DEPLOYMENT.md` for the packaging constraints and release gates. These files describe a staging package; a successful test run alone does not establish that a target host is ready for deployment.

## Limits

The package does not provide native DOCX pagination or PDF table reconstruction. OCR and legacy conversion adapters are optional. Their external tools and artifacts must be pinned, bounded, and isolated by the host-level sandbox before use.
