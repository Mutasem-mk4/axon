## 2024-05-20 - Fix terminal column alignment for colored CLI output
**Learning:** Go's tabwriter using StripEscape expects \xff to wrap *only* the ANSI escape codes. Wrapping the entire colored string results in the visible text being evaluated as 0 width, breaking alignment padding for subsequent columns.
**Action:** When adding color to tabwriter outputs, wrap the ANSI escape sequences conditionally and explicitly using \xff, keeping the visible string itself unwrapped.
