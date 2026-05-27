## 2024-05-27 - Fix ANSI escape alignment in tabwriter
**Learning:** Adding ANSI escape color codes directly within strings written to `tabwriter` breaks the alignment because the invisible escape characters are counted towards the column width, leading to misaligned columns and bad UX in CLI tables.
**Action:** Always enable `tabwriter.StripEscape` when setting up `tabwriter` and explicitly wrap only the ANSI escape sequences with `\xff` byte markers so that tabwriter correctly ignores them when calculating column padding, maintaining perfect text alignment.
