# Spamy

## Overview

Spamy is a comprehensive email analysis tool designed to help users efficiently analyze and filter emails. It performs various checks and analyses, including checking for blacklisted emails, analyzing links, inspecting attachments, and validating email headers. Spamy aims to enhance email security by identifying potentially malicious or unwanted emails.

- **Email Header Analysis**: Extracts and prints essential email header fields including From, To, Date, Message-ID, Received, DKIM-Signature, and SPF.
- **DKIM Signature Parsing**: Formats and extracts components of DKIM-Signature, including version, algorithm, canonicalization, domain, selector, headers, body hash, and signature.
- **Link Analysis**: Extracts links from emails and checks them against blacklists. Uses VirusTotal and Urlscan to evaluate link safety.
- **Attachment Analysis**: Checks file extensions against a list of known malicious extensions to detect potentially dangerous attachments.
- **Blacklisted Email Filtering**: Identifies and flags emails from blacklisted domains or addresses.
- **Configuration Management**: Supports configuration via external files for easy adjustments and scalability.

## Installation

Clone the repository:

```bash
git clone https://github.com/president-xd/spamy.git
```

## Dependencies

- `imaplib` - For connecting to the IMAP server.
- `email` - For parsing email content.
- `requests` - For making HTTP requests to security APIs.
- `hashlib` - For hashing attachment content.
- `textwrap` - For formatting output.
- `dns.resolver` - For DNS lookups (not fully implemented).
- `dkim` - For handling DKIM signatures.

## Installing dependencies

```bash
pip install -r requirements.txt
```


## Usage

After cloning the repository successfully and installing the dependencies, now below it are commands you need exceute, in order to run the software successfully.

```bash
cd Spamy
cd src
python3 spamy
```


## Contact
- **Github**: president-xd
- **mail**: mohsin-mukhtiar@protonmail.com

Thank you very much.

