# Reserve Bank of India — Cyber Security Framework in Banks (2016, revised 2023)
Source: RBI Master Direction DNBS.PD.0079/03.10.119/2016-17 (updated 2023).
Authority: Reserve Bank of India. Applies to: Commercial Banks, Cooperative
Banks, NBFCs, Payment Banks, Small Finance Banks, and other RBI-regulated
entities. This file contains the canonical rules SentinelAI enforces when the
sector is "indian_banking" or "banking" with indian_jurisdiction=true.

## Chapter II — Governance and Risk Management
Banks must have a Board-approved Cyber Security Policy, an executive-level
function (CISO), and a Cyber Crisis Management Plan (CCMP).

## Chapter III — IT and IS Audit
Annual IS audit by an independent auditor. All critical IT assets must be
covered. Audit findings must be tracked to closure.

## Chapter IV — Network Security
- Segregation of production and development environments.
- Whitelisting of applications on endpoints.
- No internet access for privileged accounts.
- DMZ and firewall at every ingress point.

## Chapter V — Security Operations Center (SOC)
- 24x7 SOC monitoring.
- All security events logged with timestamps.
- Mean time to detect (MTTD) and mean time to respond (MTTR) KPIs.

## Chapter VI — Vulnerability Management
- Quarterly vulnerability assessment (VA) and penetration testing (PT).
- Annual red-team exercises.
- Patch management with SLA-based remediation timelines.

## Chapter VII — Data Security
- Cardholder data and customer credentials must NEVER be stored in plaintext.
- All sensitive data must be encrypted at rest (AES-256) and in transit (TLS 1.2+).
- Production data must NEVER be used in non-production environments.

## Chapter VIII — Third-Party Risk
Banks must conduct due diligence on all third-party service providers handling
customer data, and ensure contractual security obligations.

## Chapter IX — Incident Response
Breach reporting to RBI within 2 to 6 hours of detection, depending on severity.
Customer notification without undue delay.

## Chapter X — Customer Education
Annual customer awareness programme on phishing, vishing, and social engineering.

## Annex — Key Controls
- No hardcoded secrets, API keys, or database credentials in source code.
- Multi-factor authentication on all administrative and customer-facing endpoints.
- Session timeout on all authenticated portals.
- Audit trail of all privileged operations.
