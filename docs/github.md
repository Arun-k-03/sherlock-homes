# GitHub repository settings (recommended)

Do not apply these unless you have admin access and intend to. This document is advice only.

## Branch protection for `main`

- Require a pull request before merge
- Require status checks: CI `test` job (Windows, Ubuntu, macOS)
- Require conversation resolution
- Do not allow force pushes
- Do not allow branch deletion
- Restrict who can push to `main`

## Release flow

```
feature/*  →  pull request  →  CI  →  main
  →  version bump + CHANGELOG
  →  git tag vX.Y.Z
  →  release workflow
  →  GitHub Release artifacts
```

Do not tag merely because `cargo build` succeeded.

## After creating the GitHub repository

If this clone has **no** `origin`:

```bash
git remote add origin git@github.com:<YOU>/<REPO>.git
git push -u origin main
```

Do not overwrite an existing remote URL.
