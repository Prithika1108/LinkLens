# 🔗 LinkLens – Suspicious URL Detector

## 📌 Project Overview

LinkLens is a rule-based cybersecurity web application designed to analyze URLs and identify suspicious characteristics before a user opens a link.

The system analyzes different URL features, calculates a risk score from 0 to 100, and classifies the URL as **SAFE, SUSPICIOUS, or HIGH RISK**.

---

## 🎯 Problem Statement

Users frequently receive links through emails, SMS, WhatsApp and social media. Some links may lead to phishing or fraudulent websites.

Many users cannot easily identify whether a URL is trustworthy before clicking it.

LinkLens provides a simple way to analyze a URL before opening it.

---

## 💡 Proposed Solution

LinkLens analyzes the structure of a URL using predefined cybersecurity rules.

It checks characteristics such as:

- HTTP instead of HTTPS
- IP addresses instead of domain names
- Suspicious keywords
- Very long URLs
- Multiple subdomains
- Suspicious TLDs
- Punycode domains
- URL shortening services
- Excessive special characters
- Unusual numbers in domains

The detected indicators are converted into a risk score.

---

## ⚙️ How It Works

```text
User enters URL
       ↓
URL Parsing
       ↓
Security Feature Detection
       ↓
Risk Score Calculation
       ↓
Risk Classification
       ↓
Display Result and Reasons
       ↓
Store Scan in SQLite
