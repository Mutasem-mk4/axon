## 2024-05-24 - Avoid Memory Overhead from Value Iteration of Large Structs
**Learning:** Iterating over slices of large structs (like `evidence.Finding`) using value semantics (`for _, item := range slice`) causes expensive memory allocations and copies. Additionally, storing large structs directly as values in maps (`map[Key]Struct`) compounds this overhead.
**Action:** Use index-based iteration (`for i := range slice`) with pointer access (`&slice[i]`), and store slice indices (`map[Key]int`) instead of struct values in maps to eliminate unnecessary memory allocation and value copying.
