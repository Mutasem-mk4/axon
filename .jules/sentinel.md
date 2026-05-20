## 2026-05-20 - Enforce Strict File Permissions
**Vulnerability:** Weak file permissions on security reports and application logs allowing unauthorized local read access.
**Learning:** os.Create defaults to 0666 before umask. Explicit restrictive permissions (0600) are required for sensitive output.
**Prevention:** Always use os.OpenFile with 0600 mode for files and 0700 for directories when writing sensitive data.
