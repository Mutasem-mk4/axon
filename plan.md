1. Use `replace_with_git_merge_diff` to change `uses: ./axon` to `uses: ./` in `.github/workflows/axon-scan.yml` to correctly reference the local custom action located in the root directory.
2. Use `replace_with_git_merge_diff` to change the `format: 'sarif'` input for Trivy action to `format: 'json'` and update `output: 'trivy-results.json'` since Trivy outputs JSON, and update the `input-path` to `trivy-results.json` in `.github/workflows/axon-scan.yml`.
3. Use `run_in_bash_session` to verify `.github/workflows/axon-scan.yml` has been updated successfully.
4. Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.
5. Use `submit` to submit the PR with the UX improvement and CI fixes.
