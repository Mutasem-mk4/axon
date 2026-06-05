## 2024-06-05 - Avoid value semantics for large struct slices
**Learning:** The `evidence.Finding` struct is 680 bytes. Iterating over slices of these using `for _, finding := range findings` creates a 680-byte copy on the stack for every single element, causing massive memory allocation and CPU overhead during policy evaluation and comparisons.
**Action:** Always use index-based iteration (`for i := range findings`) when looping over slices of large structs, allowing direct memory access without the implicit copy overhead.
