# cwatch

A simple tool to regurarly run queries against [cyberbro](https://github.com/stanfrbd/cyberbro) and generate a report.

## Configuration

Create a directory where you like to store your configuration and database. Create a configuration file named _cwatch.toml_ in that directory, an example is available in the file _example-config.toml _.

Change _domains_ to the domains (or hosts) you like to monitor.

## Install

Run the following in the directory where you have placed _cwatch.toml_.

```
uv venv
uv pip install cwatch
```

## Usage

Run *cwatch*:

```
uv run cwatch
```

Designed to be run from *cron*.
