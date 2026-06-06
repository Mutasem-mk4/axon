## 2024-06-06 - Fix ANSI color formatting and column alignment in tabwriter
**Learning:** In Go, when using `tabwriter` with ANSI escape codes, you must enable `tabwriter.StripEscape` and wrap *only* the exact escape sequence in `\xff` byte markers (e.g., `\xff\x1b[31m\xff`). Wrapping the entire string including visible text breaks table column padding.
**Action:** When implementing CLI UX with colored text in tables, always use the `tabwriter.StripEscape` flag and precisely target only the ANSI codes with `\xff` to maintain perfect column alignment.
