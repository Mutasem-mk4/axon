## 2024-05-24 - Fix Tabwriter Alignment
**Learning:** When using ANSI escape codes with Go's text/tabwriter, wrapping the exact escape sequence in '\xff' and using the tabwriter.StripEscape flag fixes column misalignment.
**Action:** Always use tabwriter.StripEscape and '\xff' wraps for ANSI colors in tabwriter.
