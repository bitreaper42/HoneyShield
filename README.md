# HoneyShield

HoneyShield is a multi-layer, honeypot-driven threat intelligence concept for detecting and neutralizing fake YONO APK campaigns that target SBI customers.

This repository contains the project abstract and a concise technical overview derived from it.

## Repository Contents

- `Abstract.pdf`: original project abstract document
- `README.md`: summary of the problem, proposed architecture, and response workflow

## Problem Statement

Fraud campaigns impersonating SBI YONO frequently distribute malicious APKs through SMS, WhatsApp, and phishing email. These campaigns often use urgency-driven social engineering such as fake KYC suspension notices to trick victims into installing malware and surrendering credentials or OTPs.

HoneyShield is designed to detect these campaigns early, collect actionable threat artifacts, and turn attacker interaction into intelligence that can support rapid blocking and law-enforcement action.

## Core Idea

The framework uses a two-stage honeypot model:

1. A lure layer attracts scammers and captures malicious content.
2. An analysis and credential-honeypot layer observes attacker behavior and produces attribution data.

The concept is inspired by a trap pattern: attract the attacker first, then instrument the point at which they attempt to exploit the stolen data.

## Proposed Architecture

### 1. Multi-Channel Honeypot Collection

The collection layer seeds controlled bait assets across public channels:

- Virtual phone numbers placed in SBI-related bait contexts
- WhatsApp Business API bot responses to extend attacker interaction
- Honeypot email accounts for phishing collection

This layer captures:

- Fraudulent messages
- Malicious URLs
- APK payloads
- Email attachments
- Sender and delivery metadata

All collected artifacts are routed to a centralized threat intelligence server.

### 2. Sandbox Analysis and Credential Honeypot

Captured APKs are detonated in an isolated sandbox for both static and dynamic analysis. The intent is to identify:

- Command-and-control infrastructure
- Dangerous permissions
- Runtime network behavior
- Other malware indicators

The analyzed application is then supplied with SBI-provisioned honeypot credentials linked to virtual numbers. OTP injection simulates real-world device behavior. If the attacker attempts to use those tagged credentials on the legitimate YONO portal, the system can capture high-value telemetry such as:

- Source IP address
- Device fingerprint
- Approximate geolocation

## Ecosystem Response

The abstract proposes immediate downstream response once a malicious artifact is identified:

- Push malicious domains to ISP-level DNS blocklists
- Submit URLs to Google Safe Browsing
- Report spoofed sender IDs to TRAI through Chakshu
- Share APK hashes with YONO backend systems
- Surface all intelligence in a fraud operations dashboard

The operating assumption is that fraud campaigns are high-volume and time-sensitive, so takedown speed matters as much as detection quality.

## Intended Outcomes

- Earlier detection of fake YONO APK campaigns
- Faster blocking of malicious infrastructure
- Better attribution of fraud operators
- Centralized visibility for analysts and responders
- Improved coordination with law enforcement and platform defenders

## Notes

This repository currently captures the project abstract and its conceptual design. It does not yet contain implementation code, deployment assets, or production integrations.
