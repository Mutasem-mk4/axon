## 2025-02-12 - Prevent Expensive Struct Copying in finding Iteration
**Learning:** Found multiple places iterating over `[]evidence.Finding` (a large struct) using value semantics `for _, item := range findings`. Go copies the entire large struct for every loop iteration, which causes unnecessary memory allocations and garbage collection pressure, particularly on critical paths like exporters where finding slices can be huge (e.g. 1M findings).
**Action:** Replace `for _, item := range findings` with index-based iteration `for i := range findings` and use `&findings[i]` without copying.
