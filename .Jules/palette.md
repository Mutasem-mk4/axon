## 2024-05-21 - [Fix tabwriter alignment with ANSI colors]
**Learning:** When formatting terminal output with Go's text/tabwriter and ANSI color codes, wrapping the entire colored text in \xff causes the tabwriter to evaluate the visible text's width as 0, breaking column padding. We must only wrap the ANSI escape codes themselves (e.g. \xff\x1b[31m\xff).
**Action:** Use tabwriter.StripEscape and conditionally wrap exact ANSI sequences with \xff for terminal output.
