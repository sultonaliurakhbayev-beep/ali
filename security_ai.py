import re
from urllib.parse import urlparse
import requests

class SecurityAI:
    def __init__(self):
        self.required_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Strict-Transport-Security",
        ]

    def analyze_password(self, password: str) -> dict:
        score = 0
        messages = []

        if len(password) >= 12:
            score += 3
        elif len(password) >= 8:
            score += 2
        else:
            messages.append("Password is too short. Use at least 12 characters.")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            messages.append("Add an uppercase letter.")

        if re.search(r"[a-z]", password):
            score += 1
        else:
            messages.append("Add a lowercase letter.")

        if re.search(r"\d", password):
            score += 1
        else:
            messages.append("Add a number.")

        if re.search(r"[^A-Za-z0-9]", password):
            score += 1
        else:
            messages.append("Add a symbol for extra strength.")

        if password.lower() in ["password", "123456", "admin", "letmein"]:
            messages.append("Avoid weak common passwords.")
            score = min(score, 2)

        rating = "Weak"
        if score >= 6:
            rating = "Strong"
        elif score >= 4:
            rating = "Moderate"

        return {
            "rating": rating,
            "score": score,
            "messages": messages or ["Password looks good. Consider using a password manager."],
        }

    def analyze_headers(self, headers: dict) -> dict:
        findings = []
        normalized = {k.lower(): v for k, v in headers.items()}

        for header in self.required_headers:
            if header.lower() not in normalized:
                findings.append(f"Missing security header: {header}.")

        if "content-security-policy" in normalized:
            policy = normalized["content-security-policy"]
            if "unsafe-inline" in policy or "unsafe-eval" in policy:
                findings.append("CSP allows unsafe sources; tighten your Content-Security-Policy.")

        if "x-frame-options" in normalized and normalized["x-frame-options"].lower() == "allow":
            findings.append("X-Frame-Options allows framing; set it to DENY or SAMEORIGIN.")

        return {
            "headers": {header: normalized.get(header.lower(), "Not set") for header in self.required_headers},
            "findings": findings or ["All key headers are present. Verify values for your deployment."],
        }

    def analyze_html(self, html: str) -> dict:
        issues = []
        html = html.strip()

        if not html:
            return {"findings": ["No HTML content provided."]}

        if "<form" in html and "csrf" not in html.lower():
            issues.append("A form was detected without an obvious CSRF token. Add CSRF protection.")

        if re.search(r"<script[^>]+src=[\'"][^\'\"]+\.js[\'"]", html, re.IGNORECASE):
            issues.append("Detect referenced JavaScript files. Audit third-party scripts for trust and integrity.")

        if re.search(r"<input[^>]+type=[\'"]password[\'"]", html, re.IGNORECASE) and "autocomplete=off" not in html.lower():
            issues.append("Password fields should include autocomplete=off for sensitive forms.")

        if re.search(r"http://", html, re.IGNORECASE):
            issues.append("HTTP resources were found; prefer HTTPS-only content.")

        return {"findings": issues or ["No obvious HTML security issues found; review dynamic content sources separately."]}

    def analyze_url(self, url: str) -> dict:
        result = {"url": url, "status": "unknown", "headers": {}, "findings": []}

        if not urlparse(url).scheme:
            url = f"https://{url.strip()}"

        try:
            response = requests.get(url, timeout=10, verify=False)
            result["status"] = response.status_code
            result["headers"] = dict(response.headers)
            result["findings"] = self.analyze_headers(response.headers)["findings"]

            if "text/html" in response.headers.get("Content-Type", ""):
                html_findings = self.analyze_html(response.text)["findings"]
                result["findings"].extend(html_findings)

        except requests.RequestException as exc:
            result["status"] = "error"
            result["findings"] = [f"Unable to fetch URL: {exc}"]

        return result
