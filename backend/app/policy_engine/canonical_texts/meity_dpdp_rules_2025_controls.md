# SentinelAI — MeitY DPDP Act and Rules 2025 Control Pack

## Status and provenance

- Authority: Ministry of Electronics and Information Technology (MeitY), Government of India.
- Frameworks: Digital Personal Data Protection Act, 2023 and Digital Personal Data Protection Rules, 2025.
- Rules source: `https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf`
- Active use: technical compliance assessment only; this is not legal certification.
- Applicability: activate after repository evidence indicates processing of digital personal data in scope. Return `UNKNOWN` when an organisational control cannot be demonstrated from repository evidence, and `NOT_APPLICABLE` when the framework does not apply.

## Rule 6 — reasonable security safeguards

### DPDP-R06-SEC-01 — Protect stored and transmitted personal data

Repository checks: encryption or protective configuration evidence; insecure transport/disabled certificate verification; plaintext sensitive-data markers; secret/key handling.

Source: DPDP Rules 2025, Rule 6, p. 26; DPDP Act 2023, section 8/9 safeguards.

### DPDP-R06-AC-02 — Enforce access control

Repository checks: authentication, authorization, role/permission enforcement, sensitive-route protection, and least-privilege evidence.

Source: DPDP Rules 2025, Rule 6, p. 26.

### DPDP-R06-LOG-03 — Maintain security logging and review capability

Repository checks: security-relevant access/audit logs and protected monitoring hooks. Operational log retention remains `UNKNOWN` without deployment evidence.

Source: DPDP Rules 2025, Rule 6, p. 26.

### DPDP-R06-BCP-04 — Support backup and recovery safeguards

Repository checks: backup/recovery configuration or services. A deployed backup practice cannot be proved from source alone.

Source: DPDP Rules 2025, Rule 6, p. 26.

### DPDP-R06-PROC-05 — Safeguard processor integrations

Repository checks: identify external processor integrations and security configuration. Contractual safeguards remain `UNKNOWN` without organisational evidence.

Source: DPDP Rules 2025, Rule 6, p. 26.

## Rule 7 — personal-data breach notification

### DPDP-R07-BREACH-01 — Provide breach-response workflow evidence

Repository checks: detection, incident workflow, evidence capture, affected-user notification capability, and Board-notification integration. The 72-hour operational obligation cannot be proven by source code alone.

Source: DPDP Rules 2025, Rule 7, pp. 26–27.

## Act rights and lifecycle controls

### DPDP-ACT-NOTICE-01 — Publish privacy/notice capability

Repository checks: privacy notice, data categories/purpose, and contact/rights information where applicable.

Source: DPDP Act 2023, sections 5–6; DPDP Rules 2025 notice requirements.

### DPDP-ACT-ERASURE-02 — Provide purpose-based deletion / erasure capability

Repository checks: account or personal-data erasure path and authorised deletion workflow. Downstream processor deletion and legal-retention exceptions may require non-code evidence.

Source: DPDP Act 2023, sections 8 and 12; DPDP Rules 2025 retention/erasure provisions.

## Conditional controls retained outside the active baseline

IT Rules 2021, Government OSS policy, NIC password policy, government e-mail/domain policies, PKI/certifying-authority rules, and blocking rules must be activated only after the Applicability Engine identifies their specific entity/context. They are not generic failures for ordinary commercial software.
