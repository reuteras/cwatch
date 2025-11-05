# cwatch

A simple tool to regurarly run queries against [cyberbro](https://github.com/stanfrbd/cyberbro) and generate a report.

## Configuration

Create a directory where you like to store your configuration and database. Create a configuration file named _cwatch.toml_ in that directory, an example is available in the file _example-config.toml_.

Change _domains_ to the domains (or hosts) you like to monitor.

## Install

Run the following in the directory where you have placed _cwatch.toml_.

```bash
uv venv
uv pip install cwatch
```

## Usage

Run __cwatch__:

```bash
uv run cwatch
```

Designed to be run from __cron__.

## Development

For information about contributing to this project, see [CONTRIBUTING.md](CONTRIBUTING.md).

For information about the release process, see [RELEASING.md](RELEASING.md).

Changes are tracked in [CHANGELOG.md](CHANGELOG.md).
