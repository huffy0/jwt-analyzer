# JWT Security Analyzer

A command-line tool that decodes JSON Web Tokens (JWTs) and analyzes them for common security vulnerabilities.

## What is a JWT?

JSON Web Tokens are a widely used standard for authentication and authorization in web applications and APIs. A JWT has three base64url-encoded parts separated by dots:

```
header.payload.signature
```

- **Header** - specifies the signing algorithm (e.g. HS256, RS256)
- **Payload** - contains claims: user identity, roles, expiry time
- **Signature** - verifies the token hasn't been tampered with

Because JWTs are self-contained and stateless, a misconfigured token can be exploited without ever touching a database.

---

## Vulnerabilities Detected

| Finding | Severity | Description |
|---|---|---|
| `alg: none` | 🔴 Critical | Signature verification is skipped entirely - token can be forged |
| No `exp` claim | 🔴 High | Token never expires - valid forever if stolen |
| Expired token | 🔴 High | Token is past its expiry date |
| Weak algorithm (HS256) | 🟡 Low | Symmetric key - brute-forceable if the secret is weak |
| Missing `iss` / `sub` / `aud` | 🟡 Low | Missing standard claims reduce token validation robustness |
| Asymmetric algorithm | 🟢 Info | RS256/ES256 detected - generally more secure |

---

## Installation

```bash
git clone https://github.com/huffy0/jwt-analyzer.git
cd jwt-analyzer
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

**Decode and analyze a token:**
```bash
python cli.py <your_jwt_token>
```

**With signature verification:**
```bash
python cli.py <your_jwt_token> --secret "your-secret-key"
```

**Example output:**
```
=======================================================
         JWT SECURITY ANALYZER REPORT
=======================================================

[HEADER]
  alg: HS256
  typ: JWT

[PAYLOAD]
  sub: 1234567890
  name: John Doe
  admin: True
  iat: 1516239022

[SIGNATURE]
  Not verified (no secret provided).

[SECURITY FINDINGS]
  ⚡  LOW: HS256 is symmetric - server secret must be kept safe. Brute-forceable if weak.
  ✗  HIGH: No expiration ('exp') claim - token never expires.
  ⚡  LOW: Missing 'iss' claim (issuer/subject/audience).
  ⚡  LOW: Missing 'aud' claim (issuer/subject/audience).
=======================================================
```

---

## Attack Scenarios

**`alg:none` bypass** - An attacker strips the signature and sets `"alg": "none"` in the header. Vulnerable servers skip verification entirely, accepting a forged token with any payload (e.g. `"admin": true`).

**Brute-force with HS256** - HS256 uses a shared secret. If that secret is weak (e.g. `secret`, `password123`), an attacker can crack it offline using tools like `hashcat` and forge valid tokens.

**No expiry** - A stolen token without an `exp` claim remains valid indefinitely. Combined with no token revocation, an attacker has permanent access.

---

## Dependencies

- [`PyJWT`](https://pyjwt.readthedocs.io/) - signature verification
- [`colorama`](https://pypi.org/project/colorama/) - terminal colors

---

## References

- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PortSwigger - JWT Attacks](https://portswigger.net/web-security/jwt)
