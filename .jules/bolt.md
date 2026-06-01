## 2024-06-01 - Avoid Large Struct Copying in Slice Iteration

**Learning:** When iterating over slices of large structs like `evidence.Finding`, standard value-based iteration (`for _, finding := range slice`) causes expensive memory allocations by copying the struct for each iteration. Similarly, storing the struct values in intermediate maps (e.g., `map[Key]Struct`) compounds this overhead. This is a critical performance trap in Go code processing large finding sets.

**Action:** Use index-based iteration (`for i := range slice`) and access the elements directly via `slice[i]` or pointers (`&slice[i]`). If storing slice elements in a map is necessary for quick lookups or correlation, store the integer index (`map[Key]int`) instead of copying the struct itself.
