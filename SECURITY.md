# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub: open this
repository's **Security** tab and choose **Report a vulnerability**. Do not
open a public issue for a suspected vulnerability.

Include what you found, the steps to reproduce it, and the commit you tested.
You can expect an acknowledgement within five business days.

## Scope

The Tenant Analyzer is a local console: it runs on `127.0.0.1`, holds
Checkmarx One credentials only in memory, and caches tenant data in SQLite
files under `data/`. Reports about credential handling, the local web UI
(XSS, CSRF), outbound requests to non-Checkmarx hosts, or the local data
cache are all in scope.

## Supported versions

Only the latest commit on `main` receives fixes.
