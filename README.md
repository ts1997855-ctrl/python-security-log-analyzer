# Python Security Log Analyzer

A Python-based cybersecurity project that analyzes security log files to identify suspicious login activity and generate security alerts.

## Overview

This project reads a sample security log file, analyzes authentication and file-access events, groups failed login attempts by IP address, assigns alert severity levels, and generates a security analysis report.

## Features

- Reads security log files
- Counts successful and failed logins
- Tracks file access events
- Groups failed logins by IP address
- Detects repeated failed-login activity
- Generates severity-based security alerts
- Automatically creates a security report

## Project Structure

```text
python-security-log-analyzer/
├── log_analyzer.py
├── README.md
├── sample_logs/
│   └── security.log
└── output/
    └── security_report.txt