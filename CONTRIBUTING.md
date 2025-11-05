# Contributing to cwatch

Thank you for contributing to cwatch! This document provides guidelines for contributing to the project.

## Conventional Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/) to automate changelog generation and version bumping.

### Commit Message Format

Each commit message should follow this format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Commit Types

The commit type must be one of the following:

- **feat**: A new feature (triggers a MINOR version bump)
- **fix**: A bug fix (triggers a PATCH version bump)
- **perf**: A performance improvement
- **revert**: Reverts a previous commit
- **docs**: Documentation only changes
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **style**: Changes that don't affect code meaning (white-space, formatting, etc.)
- **test**: Adding missing tests or correcting existing tests
- **build**: Changes that affect the build system or external dependencies
- **ci**: Changes to CI configuration files and scripts
- **chore**: Other changes that don't modify src or test files

### Breaking Changes

To trigger a MAJOR version bump, add `BREAKING CHANGE:` in the commit footer or add `!` after the type:

```
feat!: change API to use async/await

BREAKING CHANGE: All synchronous methods have been removed
```

### Examples

**Adding a new feature:**
```
feat: add retry logic with exponential backoff

Implements automatic retry for network operations with configurable
backoff delays to handle temporary failures gracefully.
```

**Fixing a bug:**
```
fix: prevent crash when DNS lookup fails

Previously, DNS lookup failures would call sys.exit() and crash
the entire program. Now it logs the error and continues with
other targets.
```

**Improving performance:**
```
perf: optimize database queries for change detection

Use indexed queries to speed up change detection by 50%.
```

**Documentation update:**
```
docs: add examples for cron configuration

Add example crontab entries for common use cases.
```

**Refactoring code:**
```
refactor: extract error handling into decorator

Move retry logic into a reusable decorator to reduce code duplication.
```

**Breaking change:**
```
feat!: change configuration file format to YAML

BREAKING CHANGE: Configuration files must now use YAML format instead
of TOML. See migration guide in docs/migration.md.
```

## Development Workflow

1. **Fork and clone** the repository
2. **Create a branch** for your changes: `git checkout -b feature/your-feature-name`
3. **Make your changes** following the coding standards
4. **Write tests** if applicable
5. **Run linters**: `uv run ruff check src/`
6. **Commit your changes** using conventional commits
7. **Push to your fork**: `git push origin feature/your-feature-name`
8. **Create a Pull Request** to the main repository

## Release Process

Releases are fully automated using Release Please:

1. **Commit your changes** using conventional commits to the `main` branch
2. **Release Please** automatically creates/updates a release PR
3. The PR includes:
   - Updated `CHANGELOG.md`
   - Updated version in `pyproject.toml`
   - All commits since the last release
4. **Review and merge** the release PR
5. **Upon merge**, a release is automatically:
   - Created on GitHub
   - Published to PyPI
   - Tagged with the version number

You don't need to manually:
- Update the changelog
- Bump the version
- Create git tags
- Publish to PyPI

Just write good commit messages and everything else is automated!

## Code Style

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Add docstrings to functions and classes (Google style)
- Keep functions focused and small
- Maximum line length: 120 characters (enforced by Ruff)

## Questions?

If you have questions about contributing, please open an issue on GitHub.
