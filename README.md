# cwatch

A simple tool to regurarly run queries against [cyberbro](https://github.com/stanfrbd/cyberbro) and generate a report.

## Configuration

Create a directory where you like to store your configuration and database. Create a configuration file named _cwatch.conf_ in that directory, an example is available below.

```
[iocs]
domains = [ "example.com", "example.net" ]

[cyberbro]
url = "http://127.0.0.1:5000"
engines = ["reverse_dns", "rdap", "ipquery", "abuseipdb", "ipinfo", "virustotal", "spur", "google_safe_browsing", "shodan", "phishtank", "threatfox", "urlscan", "google", "github", "ioc_one_html", "ioc_one_pdf", "abusix"]

[osint]
header = "Report for example.com"
footer = ""
ignore_engines = ["$delete", "reverse_dns", "ipquery", "ipinfo", "urlscan", "spur" ]
report = true
simple = false
verbose = false
DB_FILE = "cwatch.db"
```

Change _domains_ to the domains (or hosts) you like to monitor.

## Usage

```

```
