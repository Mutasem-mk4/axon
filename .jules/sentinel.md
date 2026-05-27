## 2026-05-27 - Restrict log and report file permissions
**Vulnerability:** Log files and security scan outputs were being created with overly permissive settings (0644 for files, 0755 for directories).
**Learning:** Default `os.Create` and `0644`/`0755` permissions expose sensitive data to any user on the system, which is dangerous for security-related apps like Axon.
**Prevention:** Always use `0600` for sensitive files and `0700` for sensitive directories. Use `os.OpenFile` with explicit permissions instead of `os.Create`.
