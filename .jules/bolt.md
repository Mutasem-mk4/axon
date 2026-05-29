## 2024-05-18 - Optimize Large Struct Storage in Maps
**Learning:** Storing large struct values like `evidence.Finding` (680 bytes) directly in Go maps by value causes massive memory overhead through copying, especially during high-throughput policy evaluation operations.
**Action:** Replace `map[Key]Struct` with `map[Key]int` and iterate via slice indices (e.g. `for i := range slice`) to map back to the original slice elements, drastically reducing memory allocations and copy operations.
