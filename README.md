# Secure E-Voting System 🔒

A secure, web-based electronic voting application built with **Python** and **Flask**. This system implements **Shamir's Secret Sharing (SSS)** cryptography to ensure vote privacy, integrity, and secure tallying without a single point of failure.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web_App-000000?style=for-the-badge&logo=flask)
![Cryptography](https://img.shields.io/badge/Crypto-Shamir's_Secret_Sharing-red?style=for-the-badge)

## 📖 Overview

The **Secure E-Voting System** simulates a privacy-preserving election process. Instead of storing votes directly, the system splits sensitive vote data using **Shamir's Secret Sharing** scheme. This ensures that no single entity can access the raw votes until a threshold of shares is combined during the tallying phase.

##  Key Features

* **User Registration:** Secure voter registration system to manage eligibility (`templates/register.html`).
* **Cryptographic Voting:** Votes are encrypted and split into "shares" upon casting, maintaining anonymity (`shamir_lib.py`).
* **Automated Tallying:** Secure reconstruction of votes from shares to compute the final election results (`templates/tally.html`).
* **Verifiable Audit Log:** A tamper-evident audit trail allows administrators to verify system integrity (`templates/audit.html`).
* **JSON Data Storage:** Lightweight, file-based storage for voter registries and audit logs (`data/regmap.json`, `data/audit.json`).

##  Tech Stack

* **Backend:** Python, Flask
* **Cryptography:** PyCryptodome (AES, Random), Shamir's Secret Sharing
* **Frontend:** HTML5, CSS3
* **Data Storage:** JSON

##  Project Structure

```bash
Secure-EVoting-System/
├── app.py                 # Main Flask application controller
├── shamir_lib.py          # Cryptographic implementation of SSS
├── generate_meta.py       # Helper script for metadata generation
├── templates/             # HTML Frontend Templates
│   ├── index.html         # Home Dashboard
│   ├── register.html      # Voter Registration
│   ├── vote.html          # Voting Interface
│   ├── voted.html         # Confirmation Page
│   ├── tally.html         # Election Results
│   ├── audit.html         # System Logs
│   ├── issued.html        # Token Issuance
│   └── layout.html        # Base Template
├── data/                  # Data Storage (JSON)
│   ├── audit.json         # Audit logs
│   ├── meta.json          # Election metadata
│   └── regmap.json        # Voter registry
└── README.md              # Documentation
