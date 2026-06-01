## 2024-06-01 - Fix tabwriter column alignment with ANSI colors
**Learning:** When using Go's `tabwriter` with ANSI escape codes for CLI output, the escape codes are counted as visible characters, breaking table alignment.
**Action:** Enable `tabwriter.StripEscape` and wrap *only* the exact escape sequences in `\xff` byte markers (e.g., `\xff\x1b[31m\xff`) to ensure the table aligns correctly.
