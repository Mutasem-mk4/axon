## 2025-06-05 - 🛡️ Sentinel: [CRITICAL] Prevent Insecure File Permissions for Security Reports

**Vulnerability:** Files generated for security reports (using `os.Create`) inherently get broad read permissions (usually `-rw-r--r--` depending on umask). If reports contain sensitive data like secrets or vulnerabilities, they could be read by unauthorized users on the same system.
**Learning:** `os.Create` creates files with `0666` mode which defaults to readable by everyone if umask is `0022`. Since this tool exports sensitive security reports and AI generated code fixes, we need stricter permissions.
**Prevention:** Use `os.OpenFile` with explicit permissions like `0600` for outputting sensitive files.
