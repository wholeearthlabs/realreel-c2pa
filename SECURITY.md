# Security Policy

> **Status: not yet independently audited.** This repository implements the
> cryptographic signing and verification stack behind RealReel and is published
> for transparency and community review. It has **not** undergone a formal
> third-party security audit. Use at your own risk — and please report anything
> you find.

## Reporting a vulnerability

Please report suspected security vulnerabilities **privately**. Do **not** open a
public issue, pull request, or discussion for a suspected vulnerability.

**Preferred:** use GitHub's private vulnerability reporting for this repository
(the repo's **Security → Report a vulnerability** tab).

**Alternatively, email:** security@realreel.xyz

Please include:
- a description of the issue and its impact;
- the affected component(s) — `verifier`, `native`, `ca`, or `trust-core`;
- reproduction steps or a proof of concept.

We aim to acknowledge reports within 3 business days and will keep you informed
as we investigate and remediate.

## Scope

**In scope:** the cryptographic signing and verification logic in this
repository — the verifier microservice, the native capture-signing modules, the
CA / enrollment functions, and the shared trust-core policy package.

**Out of scope:** the closed-source RealReel application, its infrastructure, and
any deployment not built from this repository.

## Coordinated disclosure

Please give us a reasonable opportunity to investigate and ship a fix before any
public disclosure. We're glad to credit reporters who would like acknowledgement.
