## 2024-05-30 - Fix Tabwriter ANSI Alignment
**Learning:** Go's `text/tabwriter` calculates cell widths based on the raw string length, including ANSI escape sequences, breaking table alignment when outputting colored text.
**Action:** Use `tabwriter.StripEscape` flag during `tabwriter` initialization and wrap ONLY the exact ANSI escape sequences in `\xff` byte markers (e.g., `\xff\x1b[31m\xff`) to ensure proper column alignment.
