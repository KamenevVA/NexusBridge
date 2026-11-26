# Contributing

This is an early development repository. Discuss substantive changes in an issue before submitting a PR. Preserve the documented security boundary and distinguish verified results from proposed functionality.

1. Create a focused branch.
2. Use Node.js 24 and install locked dependencies with `npm ci --ignore-scripts`.
3. Run `npm run typecheck` and `npm test` on Windows.
4. Add positive and negative tests for changed behavior.
5. Explain limitations, security implications and actual test results in your PR.

Use synthetic data only. Do not commit credentials, runtime directories, internal logs or screenshots. No unrestricted shell, elevation or public listener in the alpha. A contribution does not imply a license has been selected.
