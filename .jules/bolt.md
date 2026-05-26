## 2024-05-26 - Eliminate value copies of large structs

**Learning:** `evidence.Finding` is a large struct (280+ bytes). Iterating over slices of these structs using `for _, finding := range slice` and storing them in maps using `map[Key]evidence.Finding` causes significant memory allocation and CPU overhead due to implicit value copying during assignments and function calls.

**Action:** When iterating over slices of large structs, use index-based slice loops (`for i := range slice`) and reference the elements directly (`slice[i]`). When storing references in maps or tracking seen items, store the integer slice index (`map[Key]int`) instead of copying the entire struct value into the map.
