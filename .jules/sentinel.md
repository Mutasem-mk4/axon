# Sentinel Journal
## 2024-05-29 - Enforce strict file permissions for sensitive outputs
**Vulnerability:** Output files (reports, logs) were being created with permissive permissions (0666 via os.Create or 0644/0755 via os.OpenFile/MkdirAll), which could allow unauthorized local users to read sensitive security findings.
**Learning:** Default file creation methods like os.Create apply umask but often result in overly permissive files for sensitive data.
**Prevention:** Always use os.OpenFile with explicit restrict permissions (0o600 for files) and os.MkdirAll with 0o700 for directories when handling sensitive application outputs or logs.
