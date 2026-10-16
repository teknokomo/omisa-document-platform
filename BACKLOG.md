# Backlog

## Large CSV output pagination

**Priority:** P1 correctness
**Status:** Open

### Problem

A large CSV table may exceed the parser's serialized-output budget as one record. The parser can then return a truncated result without a continuation cursor, so callers cannot read the remaining rows.

### Expected behavior

Split CSV rows into bounded table records before output-byte enforcement. Preserve table identity, row ordering, and explicit row ranges. `document_read` should page through all chunks with an opaque continuation cursor when more records remain.

### Acceptance criteria

- Large CSV input produces multiple bounded table records instead of one oversized record.
- Each chunk identifies its table and row range; chunks have no overlaps or gaps.
- Row, column, cell, text, record, and serialized-output budgets are charged before materialization.
- `document_read` returns subsequent records using its opaque cursor.
- `include: [tables]` and `max_records` behave as documented.
- Exact-cap and cap-plus-one tests cover row, cell, record-byte, output-byte, and cursor boundaries.
- Small CSV behavior remains compatible.
- CSV formulas remain inert text; sanitation and sandbox boundaries remain unchanged.
