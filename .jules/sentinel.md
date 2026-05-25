## 2024-05-25 - Insecure File and Directory Permissions

**Vulnerability:** Output files and logs were created with default or overly permissive permissions (e.g., `os.Create`, `os.MkdirAll(..., 0755)`, `os.OpenFile(..., 0644)`), which could allow unauthorized local users to read sensitive security reports and application logs.
**Learning:** `os.Create` creates files with `0666` permissions (before umask), and logging setups commonly use `0644`/`0755`. This defaults to world-readable, which is a risk for a security CLI generating sensitive reports or saving logs.
**Prevention:** Always explicitly use `os.OpenFile` with the `0o600` permission mask for sensitive files and `os.MkdirAll` with `0o700` for sensitive directories.
