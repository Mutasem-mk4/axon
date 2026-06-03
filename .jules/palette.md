## 2025-02-28 - Tabwriter ANSI Escape Sequences
**Learning:** When using Go's `tabwriter` to display aligned columns in the terminal, ANSI color escape sequences are counted as visible characters by default, breaking column alignment.
**Action:** Enable `tabwriter.StripEscape` when initializing the writer, and wrap only the ANSI escape sequences with `\xff` byte markers (e.g., `\xff\x1b[31m\xff`) so they are ignored during width calculation but correctly outputted.
