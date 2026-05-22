## 2024-05-22 - Terminal Table Alignment Fix
**Learning:** When using ANSI escape codes with Go's `text/tabwriter`, the escape sequences themselves are counted towards column width, breaking alignment. Wrapping only the exact escape sequences with `\xff` (e.g., `\xff\x1b[31m\xff`) and enabling `tabwriter.StripEscape` fixes this without wrapping the visible text itself.
**Action:** Always wrap ANSI escape codes in `\xff` and enable `tabwriter.StripEscape` when printing formatted tables in the terminal to ensure proper column alignment.
