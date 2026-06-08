# Demo 01 - Basic TLS triage

A realistic, **authorized** triage scenario: a security engineer runs an
external scanner (here, simulated `sslyze`/`openssl`-style output) against a
legacy internal endpoint they are responsible for, then feeds the captured
output to SSLTRIAGE for a quick report card.

## Input

`legacy-host.sslyze.txt` is captured TLS scanner output for the host
`legacy.internal.example`. It exhibits several classic misconfigurations:

- TLS 1.0 and TLS 1.1 still offered (deprecated)
- 3DES (Sweet32) and RC4 cipher suites still negotiable
- A certificate that is close to expiry

## Run it

```sh
# Table report card
python -m ssltriage grade demos/01-basic/legacy-host.sslyze.txt

# Machine-readable JSON (for dashboards / ticket automation)
python -m ssltriage grade demos/01-basic/legacy-host.sslyze.txt --format json

# Pipe from a live (authorized) scan instead of a file
sslyze legacy.internal.example | python -m ssltriage grade -
```

## Expected outcome

- Grade lands in the **D/F** range because of the weak protocols and ciphers.
- Findings include `PROTO_INSECURE` (TLS 1.0/1.1), `CIPHER_WEAK` (RC4 / 3DES),
  and a certificate-expiry finding.
- The process exits **non-zero** (medium+ findings present), so it can gate a
  CI pipeline or a remediation ticket.

## Scope / ethics

SSLTRIAGE only *parses and grades* output you already collected from systems
you are authorized to test. It performs no scanning, no connections, and no
attacks of any kind.
