## 2024-05-20 - Index-based slice iteration for large structs in Go
**Learning:** Iterating over slices of large structs (like `evidence.Finding`) using value semantics (`for _, item := range slice`) causes expensive memory allocations and copying.
**Action:** Use index-based iteration (`for i := range slice`) and pointer semantics (`&slice[i]`) for large struct slices to prevent performance degradation.
