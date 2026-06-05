## 2024-06-05 - Fix CLI table formatting with ANSI colors
**Learning:** When using Go's `text/tabwriter` with ANSI escape codes (for colored CLI output), the ANSI codes add invisible width that breaks column alignment. Using the `tabwriter.StripEscape` flag and wrapping ONLY the ANSI sequences in `\xff` byte markers (e.g., `\xff\x1b[31m\xff`) ensures correct padding and alignment.
**Action:** Always enable `tabwriter.StripEscape` and wrap color sequences in `\xff` when printing tables with colors in CLI apps.
