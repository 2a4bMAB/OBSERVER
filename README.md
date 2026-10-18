markdown
# OBSERVER 🔍

**Automated web application vulnerability audit tool.**

OBSERVER is a desktop application (Python, PyQt6) that audits web applications
against the **10 categories of the OWASP Top 10** and produces detailed,
actionable PDF reports.

## ✨ Features

- 🔎 **Multi-threaded scan engine**: crawler plus detectors for SQLi, XSS, IDOR, SSRF and more
- 📊 **Severity scoring** and **real-time logging** during scans
- 📄 **Automated PDF reports**: evidence, severity and remediation recommendations
- 🔐 **Secure authentication**: email-based two-factor authentication (2FA)
- 👥 **Role-based access** (Admin / Pentester) following the principle of least privilege
- 🗄️ **SQLite database** with session management and schema migration
- 📦 **Standalone Windows executable** built with PyInstaller

## 🧰 Tech stack

Python · PyQt6 · SQLite · PyInstaller

## ⚠️ Legal disclaimer

OBSERVER is intended for **authorized security testing only**. Only scan
applications you own or have explicit written permission to test. The author
is not responsible for misuse.
