# Changelog

## [0.4.1](https://github.com/reuteras/cwatch/compare/v0.4.0...v0.4.1) (2025-11-05)


### Documentation

* add PR description for Release Please setup ([8228b98](https://github.com/reuteras/cwatch/commit/8228b989a92a7339e8b448aaaae4fcce1fd78737))

## [0.4.0](https://github.com/reuteras/cwatch/compare/v0.2.2...v0.4.0) (2024-11-05)


### Features

* Add retry decorator with exponential backoff for network operations
* Add timeout configuration (30 seconds) for all HTTP requests
* Add comprehensive error handling for database operations
* Add error handling for file operations and configuration loading
* DNS lookups now retry with exponential backoff


### Bug Fixes

* Remove sys.exit() calls that would crash cron jobs on temporary failures
* DNS lookup failures no longer crash the entire program
* HTTP connection errors are now properly retried
* Database errors are now caught and handled gracefully
* Improve error messages and diagnostics

## [0.2.2](https://github.com/reuteras/cwatch/compare/v0.2.1...v0.2.2) (2024-10-15)


### Bug Fixes

* Add RuntimeError exception handling in handle_threatfox function

## [0.2.1](https://github.com/reuteras/cwatch/releases/tag/v0.2.1) (2024-10-01)


### Features

* Initial stable release with monitoring functionality
