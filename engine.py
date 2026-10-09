import re
from typing import List, Dict, Any

class SecurityEngine:
    # Patterns for Prompt Injection
    INJECTION_PATTERNS = [
        r"ignore (all )?previous instructions",
        r"system override",
        r"disregard (the )?above",
        r"new rule:",
        r"you are now (a|an)",
        r"dan mode",
        r"jailbreak",
    ]

    # Patterns for PII
    PII_PATTERNS = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
        "phone": r"\b\d{3}-\d{3}-\d{4}\b",
    }

    # Patterns for Privacy/Secrets
    PRIVACY_PATTERNS = {
        "api_key": r"(?:key|api|token|secret|auth)[-_=:\s]*[a-zA-Z0-9]{16,}",
        "internal_ip": r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    }

    def analyze(self, content: str) -> Dict[str, Any]:
        findings = []
        risk_score = 0

        # Check Injection
        for pattern in self.INJECTION_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append({"type": "prompt_injection", "detail": f"Matched pattern: {pattern}", "severity": "high"})
                risk_score += 50

        # Check PII
        for pii_type, pattern in self.PII_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append({"type": "pii", "detail": f"Detected {pii_type}", "severity": "medium", "count": len(matches)})
                risk_score += 20 * len(matches)

        # Check Privacy
        for priv_type, pattern in self.PRIVACY_PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append({"type": "privacy_leak", "detail": f"Detected {priv_type}", "severity": "high"})
                risk_score += 40

        return {
            "findings": findings,
            "risk_score": min(risk_score, 100),
            "status": "blocked" if risk_score >= 80 else "flagged" if risk_score > 0 else "safe"
        }
