## 2025-06-02 - Enforce strict file permissions for output files
**Vulnerability:** File creation using `os.Create` grants broad permissions (0666 before umask), potentially exposing sensitive security data in output files.
**Learning:** `os.Create` lacks explicit permission controls, making it unsuitable for files that might contain sensitive security scanning results or patches.
**Prevention:** Always use `os.OpenFile` with explicit strict permissions (e.g., `0600`) when creating output files.
