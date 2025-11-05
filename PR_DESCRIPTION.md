# Add automated release workflow with Release Please

## Summary

This PR adds a fully automated release workflow using Release Please and Conventional Commits. This eliminates manual version bumping and changelog management.

## What's Included

### New Workflow
- **`.github/workflows/release-please.yml`** - Automated release workflow that:
  - Creates/updates release PRs automatically based on conventional commits
  - Generates CHANGELOG.md from commit messages
  - Updates version in pyproject.toml
  - Publishes to PyPI on merge
  - Creates GitHub releases with changelog

### Configuration
- **`.release-please-config.json`** - Release Please configuration for Python projects
- **`.release-please-manifest.json`** - Version tracking (starts at 0.4.0)

### Documentation
- **`CONTRIBUTING.md`** - Complete guide on conventional commits with examples
- **`RELEASING.md`** - New automated release process documentation
- **`CHANGELOG.md`** - Reformatted for Release Please compatibility
- **Updated `README.md`** - Links to new documentation

## How It Works

1. **Write code** with conventional commit messages:
   ```bash
   git commit -m "feat: add new feature"
   git commit -m "fix: fix a bug"
   ```

2. **Release Please automatically**:
   - Analyzes commit messages
   - Creates/updates a release PR with:
     - Updated CHANGELOG.md
     - Updated version in pyproject.toml
     - All changes since last release

3. **Review and merge** the release PR

4. **Upon merge**, automatically:
   - Creates GitHub Release
   - Builds package with uv
   - Publishes to PyPI
   - Tags the release

## Version Bumping

Version bumps are determined by commit types:
- `fix:` → PATCH (0.4.0 → 0.4.1)
- `feat:` → MINOR (0.4.0 → 0.5.0)
- `BREAKING CHANGE:` or `!` → MAJOR (0.4.0 → 1.0.0)

## Before First Release

You need to configure PyPI publishing (one-time setup):

**Option A: Trusted Publishing (Recommended)**
1. Go to https://pypi.org/manage/account/publishing/
2. Add pending publisher:
   - Project: `cwatch`
   - Owner: `reuteras`
   - Repository: `cwatch`
   - Workflow: `release-please.yml`

**Option B: API Token**
Add `PYPI_API_TOKEN` as a GitHub secret

## Benefits

- ✅ No manual version management
- ✅ Automatic changelog generation
- ✅ Consistent release process
- ✅ Semantic versioning enforced by commit messages
- ✅ Reduces human error in releases

## Testing

All configuration files have been validated:
- ✅ YAML syntax validated
- ✅ JSON configuration validated
- ✅ Follows Release Please best practices

## Documentation

Complete documentation is available in:
- `CONTRIBUTING.md` - How to write conventional commits
- `RELEASING.md` - Complete release process guide
