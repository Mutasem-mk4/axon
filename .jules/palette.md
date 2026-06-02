## 2024-06-02 - Fix terminal table alignment broken by ANSI colors
**Learning:** Go's `text/tabwriter` miscalculates column widths when text contains ANSI color codes, breaking table alignment. `tabwriter.StripEscape` must be used along with wrapping exact escape sequences in `\xff` bytes.
**Action:** Always enable `tabwriter.StripEscape` and wrap ANSI escape sequences with `\xff` when writing colored output to a `tabwriter` to maintain consistent column alignment in CLI applications.
