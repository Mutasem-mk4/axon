## 2026-05-24 - [Strict File Permissions]
**Vulnerability:** Files were being created using `os.Create` which uses overly permissive default permissions (usually 0666 before umask), potentially exposing sensitive security report data.
**Learning:** Go's `os.Create` lacks explicit permission controls, making it unsuitable for security tooling output files.
**Prevention:** Use `os.OpenFile` with explicit `0o600` (read/write by owner only) permissions when creating sensitive output files.
