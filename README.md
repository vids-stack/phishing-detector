# phishing-detector

A simple Python tool for spotting signs of phishing in email files (`.eml`).

> **Work in progress.** This project is being built step by step, one level at a time.

## Level 1: Header and authentication checks (done)

`check_email.py` reads one email file and checks:

- **Sender addresses:** shows the From, Reply-To and Return-Path addresses, and warns if their domains don't match.
- **SPF, DKIM and DMARC:** shows whether each check passed, failed or is missing.

## How to run

You need Python 3. No extra packages are required.

```
python3 check_email.py samples/fake_phishing.eml
```

`samples/fake_phishing.eml` is a **fake** phishing email for testing. All of its domains use the reserved `.example` ending, so none of them are real.

## Coming next

More levels will be added as the project grows.
