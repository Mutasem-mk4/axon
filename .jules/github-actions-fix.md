## YYYY-MM-DD - Fix Action Checkout
**Learning:** In GitHub Actions, when referencing an action located in the root of the same repository, we must use `uses: ./` instead of `uses: ./axon`.
**Action:** Replace `uses: ./axon` with `uses: ./` in `.github/workflows/axon-scan.yml`.
