from __future__ import annotations

import re


def audit_hash(value: str) -> dict:
    value = value.strip()
    findings: list[str] = []
    algorithm = "unknown"
    recommendations: list[str] = []

    if re.fullmatch(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}", value):
        algorithm = "bcrypt"
        recommendations.append("Keep bcrypt cost appropriate for your environment; prefer Argon2id for new systems when supported.")
    elif value.startswith("$argon2id$"):
        algorithm = "Argon2id"
        recommendations.append("Argon2id is a modern password-hashing choice; review memory, time and parallelism settings.")
    elif value.startswith("$argon2i$") or value.startswith("$argon2d$"):
        algorithm = "Argon2 variant"
        findings.append("Review whether the selected Argon2 variant is appropriate for password storage.")
        recommendations.append("Prefer Argon2id for new password-storage deployments.")
    elif value.startswith("$6$"):
        algorithm = "Unix SHA-512 crypt"
        findings.append("General-purpose SHA-family password hashing is older than modern memory-hard password hashing.")
        recommendations.append("Prefer Argon2id, scrypt or bcrypt for new password storage.")
    elif value.startswith("$5$"):
        algorithm = "Unix SHA-256 crypt"
        findings.append("General-purpose SHA-family password hashing is older than modern memory-hard password hashing.")
        recommendations.append("Prefer Argon2id, scrypt or bcrypt for new password storage.")
    elif re.fullmatch(r"[0-9a-fA-F]{32}", value):
        algorithm = "MD5-shaped digest"
        findings.append("MD5 is not suitable for password storage.")
        recommendations.append("Migrate to a password-specific memory-hard scheme such as Argon2id.")
    elif re.fullmatch(r"[0-9a-fA-F]{40}", value):
        algorithm = "SHA-1-shaped digest"
        findings.append("SHA-1 is not suitable for password storage.")
        recommendations.append("Migrate to a password-specific memory-hard scheme such as Argon2id.")
    elif re.fullmatch(r"[0-9a-fA-F]{64}", value):
        algorithm = "SHA-256-shaped digest"
        findings.append("A bare SHA-256 digest is not an appropriate password-storage construction.")
        recommendations.append("Use a salted, memory-hard password hashing scheme such as Argon2id.")
    else:
        findings.append("Format could not be confidently classified.")
        recommendations.append("Verify the storage format and confirm that a per-password salt and password-specific KDF are used.")

    risk = "LOW"
    if any("not suitable" in x or "not an appropriate" in x for x in findings):
        risk = "HIGH"
    elif findings:
        risk = "MEDIUM"

    return {
        "algorithm": algorithm,
        "risk": risk,
        "findings": findings,
        "recommendations": recommendations,
        "mode": "defensive-password-storage-audit",
        "note": "Nexis does not attempt to recover passwords or attack accounts from this command.",
    }
