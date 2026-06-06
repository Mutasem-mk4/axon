## YYYY-MM-DD - Insecure file creation
**Vulnerability:** `os.Create` creates files with world-readable permissions (0666 before umask) which might leak sensitive data (e.g. security reports).
**Learning:** Security reports contain sensitive vulnerability information and should be strictly restricted to the user running the command to prevent horizontal privilege escalation or data leakage.
**Prevention:** Use `os.OpenFile` with explicit permissions `0o600` for output files instead of `os.Create`.
