## 2025-05-24 - Improve finding slice iteration performance

**Learning:** Iterating over large slices of structs like `evidence.Finding` using value semantics (`for _, finding := range ...`) causes significant memory overhead due to repeated full struct copies.
**Action:** Use index-based pointer semantics (`for i := range ...`) to access the structs instead, mitigating unnecessary CPU overhead and avoiding extensive memory copies.
