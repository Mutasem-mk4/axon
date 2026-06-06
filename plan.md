1. Use `replace_with_git_merge_diff` to remove unused `opCorrelate` constant from `internal/domain/correlation/service.go`.
2. Use `replace_with_git_merge_diff` to remove unused `acquireIdentityBuffer` function from `internal/domain/evidence/identity.go`.
3. Use `run_in_bash_session` to verify changes using `staticcheck ./...`.
4. Use `run_in_bash_session` to revert `go.mod` and `go.sum` to clean state using `git checkout HEAD -- go.mod go.sum` since tests or staticcheck execution might have downloaded new deps breaking CI check.
5. Use `submit` to submit the PR with the UX improvement and CI fixes.
