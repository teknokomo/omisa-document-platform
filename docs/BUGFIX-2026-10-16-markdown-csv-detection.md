# Markdown headings misclassified as CSV

## Problem

The text-format detector treated a comma in the first line as a reason to invoke `csv.Sniffer`. If sniffing failed, a broad fallback classified any multi-line input as CSV. Markdown headings and prose with commas therefore became tables. Converting the text into table records could also expand the normalized output enough to exceed the parser cache limit.

## Change

- Detect strong Markdown markers, including headings, fenced code blocks, and pipe tables, before testing CSV structure.
- Require multiple non-empty rows with a consistent column count before classifying text as CSV.
- Preserve comma, tab, and semicolon delimiters and use the detected delimiter during CSV parsing.
- Check weaker Markdown markers such as lists after CSV structure so valid CSV values that resemble list items remain supported.

The classifier continues to use content rather than relying on a filename extension.

## Regression coverage

Tests cover comma-bearing Markdown headings, large synthetic Markdown input, real comma-separated CSV with quoted fields, TSV, semicolon-separated CSV, and Markdown lists containing commas. No user documents are included in the repository.
