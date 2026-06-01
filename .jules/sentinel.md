## 2024-06-01 - Path Traversal and Insecure File Creation
**Vulnerability:** User-provided paths were passed directly to `os.Open` and `os.Create` without normalization (`filepath.Clean`) or type checking (`os.Stat` to verify it's not a directory). Furthermore, `os.Create` was used, which creates files with default permissions, instead of `os.OpenFile` with strict `0600` permissions.
**Learning:** We need to normalize user input paths and enforce strict file permissions when creating files.
**Prevention:** Always use `filepath.Clean(path)` on user input, verify the path using `os.Stat(path)` before using it, and use `os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)` to ensure strict permissions.
