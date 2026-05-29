import base64
import json
from datetime import datetime, timezone

def decode_part(part):
    # JWT uses base64url, need to add padding
    padding = 4 - len(part) % 4
    part += "=" * padding
    decoded = base64.urlsafe_b64decode(part)
    return json.loads(decoded)

def analyze_jwt(token, secret=None):
    results = {
        "header": None,
        "payload": None,
        "warnings": [],
        "signature_status": None
    }

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: must have 3 parts separated by dots.")

    # Decode header and payload
    results["header"] = decode_part(parts[0])
    results["payload"] = decode_part(parts[1])

    header = results["header"]
    payload = results["payload"]

    # --- Security checks ---

    # 1. alg:none attack
    alg = header.get("alg", "").lower()
    if alg == "none":
        results["warnings"].append("CRITICAL: Algorithm is 'none' — signature is not verified. Token can be forged.")

    # 2. Weak algorithm
    if alg in ["hs256"]:
        results["warnings"].append("LOW: HS256 is symmetric — server secret must be kept safe. Brute-forceable if weak.")
    if alg in ["rs256", "es256"]:
        results["warnings"].append("INFO: Asymmetric algorithm detected (good).")

    # 3. Missing expiry
    if "exp" not in payload:
        results["warnings"].append("HIGH: No expiration ('exp') claim — token never expires.")

    # 4. Expired token
    if "exp" in payload:
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        if now > exp:
            results["warnings"].append(f"HIGH: Token is EXPIRED (expired {exp.strftime('%Y-%m-%d %H:%M:%S UTC')}).")
        else:
            results["warnings"].append(f"INFO: Token expires at {exp.strftime('%Y-%m-%d %H:%M:%S UTC')}.")

    # 5. Missing standard claims
    for claim in ["iss", "sub", "aud"]:
        if claim not in payload:
            results["warnings"].append(f"LOW: Missing '{claim}' claim (issuer/subject/audience).")

    # --- Signature verification ---
    if secret:
        import jwt as pyjwt
        try:
            pyjwt.decode(token, secret, algorithms=[header.get("alg", "HS256")])
            results["signature_status"] = "VALID — signature verified with provided secret."
        except pyjwt.ExpiredSignatureError:
            results["signature_status"] = "Signature VALID but token is expired."
        except pyjwt.InvalidSignatureError:
            results["signature_status"] = "INVALID — signature does not match secret."
        except Exception as e:
            results["signature_status"] = f"ERROR during verification: {e}"
    else:
        results["signature_status"] = "Not verified (no secret provided)."

    return results