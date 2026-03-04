# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | ✅ Current |
| < 0.4   | ❌ No longer supported |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by opening a [GitHub private security advisory](https://github.com/aheissenberger/gitvault/security/advisories/new).

Include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Affected versions
- Suggested fix, if any

## Response Timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix and coordinated disclosure**: within 90 days (sooner for critical issues)

## Scope

Issues in scope:
- Secret decryption without authorization
- Identity key extraction or leakage
- Bypass of the production barrier (`allow-prod` / HMAC token)
- Path traversal or shell injection via crafted secret files or recipient keys
- Race conditions leading to secret exposure on disk

Out of scope:
- Vulnerabilities in dependencies (report those to the dependency maintainers)
- Issues requiring physical access to the machine
- Social engineering attacks
