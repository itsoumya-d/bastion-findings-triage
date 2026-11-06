# bastion-findings-triage

A TypeScript/React security findings triage dashboard: CVSS 3.1 base scoring,
asset-weighted risk, severity, duplicate suppression, remediation SLAs and
portfolio reporting.

This is an independent reference implementation for Bastion Security's
assessment and managed-security workflow.

## Why this exists

A vulnerability queue is only useful if it tells the team what to fix first.
This module parses a CVSS vector, computes the base score, weights it by the
asset's criticality and exposure, removes duplicate findings, assigns a
severity-based remediation SLA and reports the portfolio.

## Formulas

```text
ISS          = 1 - (1-C)(1-I)(1-A)
Impact       = 6.42*ISS                      (scope unchanged)
             = 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15  (scope changed)
Exploitability = 8.22*AV*AC*PR*UI
CVSS base    = roundup(min(Impact+Exploitability, 10))
             = roundup(min(1.08*(Impact+Exploitability), 10)) for scope changed
risk         = min(100, base * (criticality/5) * exposureMultiplier * 10)
SLA days     = critical 7, high 14, medium 30, low 90
```

## UI

The dashboard shows unique findings, critical count, average risk, overdue
SLAs, duplicates removed, a finding queue with CVSS/risk/severity/SLA, a
severity mix and an explanation of the triage model.

## Run

```bash
npm install
npm run dev
# or
npm run build
```

## Test

```bash
npm test
npm run build
```

Vitest covers known CVSS 3.1 vectors, invalid vectors, severity bands,
asset-criticality risk weighting, SLA days and dates, overdue/due-soon/safe
status, deduplication, portfolio counts, average risk and formatting.

## Design tokens

From Bastion's public site:

- Heading: Open Sans
- Body: Arial / Helvetica
- Ink: `#141F32`
- Deep: `#000B1F`
- Blue: `#1B6CF8`
- Green: `#00B83B`
- Surface: `#F6F8FC`
- Background: `#FFFFFF`
- Radius: `8px`
- Spacing unit: `8px`

## Stack

TypeScript, React, Vite, Vitest and GitHub Actions.
