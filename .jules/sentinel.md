## 2024-05-23 - Strict File Permissions for Output Files
**Vulnerability:** Files created with os.Create default to 0666 permissions (before umask), which may allow unauthorized local users to read sensitive security reports.
**Learning:** Default file creation methods in standard libraries often prioritize convenience over security. Security tools should explicitly enforce restrictive permissions (e.g., 0600) when writing output files.
**Prevention:** Always use os.OpenFile with explicit restrictive permissions (0o600) and the necessary flags (os.O_CREATE|os.O_WRONLY|os.O_TRUNC) instead of os.Create when generating sensitive artifacts.
