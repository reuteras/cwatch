# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Retry decorator with exponential backoff for network operations
- Timeout configuration (30 seconds) for all HTTP requests
- Comprehensive error handling for database operations
- Error handling for file operations and configuration loading
- DNS lookups now retry with exponential backoff

### Changed
- Improved resilience to temporary failures throughout the application
- Network operations now continue with other targets if one fails
- All database operations now have proper error handling
- Better error messages and diagnostics

### Fixed
- Removed `sys.exit()` calls that would crash cron jobs on temporary failures
- DNS lookup failures no longer crash the entire program
- HTTP connection errors are now properly retried
- Database errors are now caught and handled gracefully

## [0.4.0] - 2024-11-XX

### Changed
- Updated dependencies (pylint 4.0.x, ruff 0.14.x)
- Improved linter configuration

## [0.2.2] - 2024-XX-XX

### Added
- RuntimeError exception handling in handle_threatfox function

### Fixed
- Exception handling improvements

## [0.2.1] - 2024-XX-XX

### Changed
- Initial stable release with basic monitoring functionality

[Unreleased]: https://github.com/reuteras/cwatch/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/reuteras/cwatch/compare/v0.2.2...v0.4.0
[0.2.2]: https://github.com/reuteras/cwatch/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/reuteras/cwatch/releases/tag/v0.2.1
