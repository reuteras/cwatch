# Release Process

This document describes how releases work in cwatch. The process is **fully automated** using Release Please and Conventional Commits.

## How It Works

Releases are automatic! You don't manually:
- ❌ Update CHANGELOG.md
- ❌ Bump version numbers
- ❌ Create git tags
- ❌ Publish to PyPI

Instead, the system does it for you based on your commit messages.

## The Automated Process

### 1. Write Code with Conventional Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) format for your commit messages:

```bash
# Adding a new feature (triggers minor version bump: 0.4.0 → 0.5.0)
git commit -m "feat: add automatic retry for network failures"

# Fixing a bug (triggers patch version bump: 0.4.0 → 0.4.1)
git commit -m "fix: prevent crash on DNS lookup failure"

# Breaking change (triggers major version bump: 0.4.0 → 1.0.0)
git commit -m "feat!: change configuration format to YAML"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full commit message guidelines.

### 2. Push to Main Branch

```bash
git push origin main
```

### 3. Release Please Creates a PR

After your commits are pushed, **Release Please** automatically:
- Analyzes your commit messages
- Determines the next version number (based on feat/fix/BREAKING CHANGE)
- Generates/updates CHANGELOG.md
- Updates version in `pyproject.toml`
- Creates or updates a "Release PR"

The PR will be titled something like: `chore(main): release 0.5.0`

### 4. Review and Merge the Release PR

- Review the automatically generated changelog
- Check the version bump is correct
- Merge the PR when ready to release

### 5. Automatic Publication

When you merge the Release PR, the workflow automatically:
- ✅ Creates a GitHub Release with the changelog
- ✅ Builds the package with `uv`
- ✅ Publishes to PyPI
- ✅ Tags the release (e.g., `v0.5.0`)

## Version Numbers Explained

Version bumps are determined by commit types:

| Commit Type | Version Bump | Example |
|------------|--------------|---------|
| `fix:` | PATCH (0.4.0 → 0.4.1) | Bug fixes |
| `feat:` | MINOR (0.4.0 → 0.5.0) | New features |
| `BREAKING CHANGE:` or `!` | MAJOR (0.4.0 → 1.0.0) | Breaking changes |
| `docs:`, `chore:`, etc. | None | No version bump |

Multiple commits are combined. For example:
- 3 `fix:` commits + 2 `feat:` commits = MINOR bump (0.4.0 → 0.5.0)
- 1 `feat!:` commit = MAJOR bump (0.4.0 → 1.0.0)

## Examples

### Example 1: Bug Fix Release

```bash
# Make changes and commit with fix type
git commit -m "fix: handle timeout errors gracefully"
git push origin main

# Release Please creates PR: "chore(main): release 0.4.1"
# Merge the PR → v0.4.1 is automatically released
```

### Example 2: Feature Release

```bash
# Add a new feature
git commit -m "feat: add support for custom retry delays"
git push origin main

# Release Please creates PR: "chore(main): release 0.5.0"
# Merge the PR → v0.5.0 is automatically released
```

### Example 3: Multiple Changes

```bash
# Multiple commits
git commit -m "fix: improve error messages"
git commit -m "feat: add metrics tracking"
git commit -m "docs: update README with examples"
git push origin main

# Release Please combines all changes
# Creates PR: "chore(main): release 0.5.0" (feat wins over fix)
# Changelog includes all three changes
# Merge the PR → v0.5.0 is automatically released
```

## One-Time Setup for PyPI Publishing

Before your first automated release, you need to configure PyPI publishing. Choose **Option A** (recommended) or **Option B**:

### Option A: Trusted Publishing (Recommended)

1. Go to [PyPI Account Publishing](https://pypi.org/manage/account/publishing/)
2. Click "Add a new pending publisher"
3. Fill in:
   - **PyPI Project Name**: `cwatch`
   - **Owner**: `reuteras`
   - **Repository name**: `cwatch`
   - **Workflow name**: `release-please.yml`
   - **Environment name**: (leave blank)
4. Click "Add"

This is more secure and doesn't require storing secrets.

### Option B: API Token (Alternative)

1. Create a token at [PyPI Account Token](https://pypi.org/manage/account/token/)
2. Go to [GitHub Secrets Settings](https://github.com/reuteras/cwatch/settings/secrets/actions)
3. Click "New repository secret"
4. Name: `PYPI_API_TOKEN`
5. Value: Your PyPI token (starts with `pypi-`)
6. Click "Add secret"

Then update `.github/workflows/release-please.yml` to use the token:
```yaml
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    password: ${{ secrets.PYPI_API_TOKEN }}
```

## Troubleshooting

### Release PR not created

**Issue**: After pushing commits, no release PR appears.

**Solutions**:
- Wait a few minutes (the workflow may be running)
- Check the [Actions tab](https://github.com/reuteras/cwatch/actions)
- Ensure commits use conventional commit format
- Check commits have `feat:` or `fix:` type (not just `chore:` or `docs:`)

### Wrong version number in PR

**Issue**: Release Please suggests the wrong version bump.

**Solutions**:
- Check your commit messages follow the correct format
- Remember: `feat:` = minor, `fix:` = patch, `!` or `BREAKING CHANGE:` = major
- You can manually edit the release PR if needed

### PyPI publishing failed

**Issue**: Release is created on GitHub but not published to PyPI.

**Solutions**:
- Check Trusted Publishing is configured correctly on PyPI
- Or verify `PYPI_API_TOKEN` secret is set correctly
- Check the workflow logs in the Actions tab

### Need to make a manual release

**Issue**: You need to release without conventional commits.

**Solutions**:
```bash
# Manually update version in pyproject.toml
# Manually update CHANGELOG.md
git add pyproject.toml CHANGELOG.md
git commit -m "chore: release 0.5.0"
git tag v0.5.0
git push origin main --tags

# Then manually build and publish:
uv build
uv publish
```

## More Information

- [Conventional Commits](https://www.conventionalcommits.org/)
- [Release Please Documentation](https://github.com/googleapis/release-please)
- [Contributing Guidelines](CONTRIBUTING.md)
