## 2024-05-18 - Fix tabwriter formatting with ANSI escape codes
**Learning:** The `tabwriter` package breaks table alignment when standard string formatting is used with ANSI codes because escape codes add invisible characters to the string width calculation.
**Action:** When using ANSI escape codes with `tabwriter`, enable `tabwriter.StripEscape` and wrap exactly only the escape sequence strings with `\xff` byte markers (e.g., `\xff\033[31m\xff`).
