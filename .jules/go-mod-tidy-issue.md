## YYYY-MM-DD - Fix Action Checkout
**Learning:** Running `go mod tidy` in CI environments might detect an issue if the required Go toolchain downloads a newer `go1.25.x` which pulls in newer module dependencies (like `google.golang.org/protobuf`), breaking the pipeline check.
**Action:** Reverted the `protobuf` version and ran `go mod tidy` locally to sync changes without unexpectedly bumping versions causing `filedesc.newRawFile` initialization panics.
