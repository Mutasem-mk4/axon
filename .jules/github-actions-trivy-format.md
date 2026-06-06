## YYYY-MM-DD - Fix Trivy Format
**Learning:** When using the Axon GitHub action to ingest Trivy results, the Trivy scanner's output format should be set to `json` (not `sarif`) and the corresponding `input-path` in the Axon step matches the JSON output file. Also, CI `go mod tidy` check failed, indicating `go.mod`/`go.sum` are out of sync with actual deps or Go version, need to run `go mod tidy` to clean up and commit the changes.
**Action:** Update Trivy format to `json` and output file to `trivy-results.json` in `.github/workflows/axon-scan.yml`. Run `go mod tidy`.
