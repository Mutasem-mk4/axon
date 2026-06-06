## YYYY-MM-DD - Fix Unused Code Warnings
**Learning:** The project uses `staticcheck`, which fails if there are unused constants or functions. Running `go install honnef.co/go/tools/cmd/staticcheck@latest` and executing it helps to catch these issues locally.
**Action:** Removed the unused `opCorrelate` constant from `internal/domain/correlation/service.go` and the unused `acquireIdentityBuffer` function from `internal/domain/evidence/identity.go`.
