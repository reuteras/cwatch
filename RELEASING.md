# Release Process

This document describes how to create a new release of cwatch.

## Automated Release Process

The project uses GitHub Actions to automate releases. When you push a version tag, it will automatically:
1. Build the package
2. Create a GitHub release with changelog notes
3. Publish to PyPI

## Prerequisites

Before your first release, you need to set up PyPI publishing:

1. Create a PyPI API token at https://pypi.org/manage/account/token/
2. Add the token as a GitHub secret:
   - Go to: `https://github.com/reuteras/cwatch/settings/secrets/actions`
   - Click "New repository secret"
   - Name: `PYPI_API_TOKEN`
   - Value: Your PyPI token (starts with `pypi-`)

**Note:** The workflow uses Trusted Publishing (PyPI's OIDC), so you may not need a token if you set that up. See [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/).

## Step-by-Step Release

### 1. Update the version

Edit `pyproject.toml` and bump the version:

```toml
[project]
name = "cwatch"
version = "0.5.0"  # Change this
```

### 2. Update the CHANGELOG

Edit `CHANGELOG.md`:

- Move items from `[Unreleased]` section to a new version section
- Add the release date
- Update the comparison links at the bottom

Example:

```markdown
## [Unreleased]

## [0.5.0] - 2024-11-05

### Added
- Retry decorator with exponential backoff for network operations
...

[Unreleased]: https://github.com/reuteras/cwatch/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/reuteras/cwatch/compare/v0.4.0...v0.5.0
```

### 3. Commit the changes

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "Bump version to 0.5.0"
git push origin main
```

### 4. Create and push the tag

```bash
git tag -a v0.5.0 -m "Release version 0.5.0"
git push origin v0.5.0
```

### 5. Monitor the release

- GitHub Actions will automatically run: https://github.com/reuteras/cwatch/actions
- Check the release appears: https://github.com/reuteras/cwatch/releases
- Verify PyPI publication: https://pypi.org/project/cwatch/

## Manual Release (Fallback)

If the automated release fails, you can publish manually:

```bash
# Build the package
uv build

# Publish to PyPI
uv publish
# Or: python -m twine upload dist/*
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version (1.0.0): Incompatible API changes
- **MINOR** version (0.5.0): New functionality, backwards compatible
- **PATCH** version (0.4.1): Bug fixes, backwards compatible

## Troubleshooting

### Version mismatch error

If the workflow fails with a version mismatch:
- Ensure `pyproject.toml` version matches the git tag
- If tag is v0.5.0, version should be "0.5.0" (without the 'v')

### PyPI authentication failed

If PyPI publishing fails:
- Check that `PYPI_API_TOKEN` secret is set correctly
- Or set up Trusted Publishing on PyPI for this repository

### Build failed

If the build fails:
- Test locally first: `uv build`
- Check that all tests pass: `uv run pytest` (if tests exist)
- Verify linting passes: `uv run ruff check src/`
