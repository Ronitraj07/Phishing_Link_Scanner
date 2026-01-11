import os
import re
import json
import base64
import logging
from datetime import datetime
from urllib.parse import urlparse, urlunparse

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLPhishingScanner:
    def __init__(self):
        # Only truly trusted roots should short-circuit to SAFE
        self.trusted_roots = {
            "google.com",
            "microsoft.com",
            "apple.com",
            "github.com",
            "stackoverflow.com",
            "wikipedia.org",
        }

        # High-risk hosting / free site platforms (phish commonly hosted here)
        self.free_hosting_domains = {
            "ucoz.ua", "ucoz.ru", "ucoz.kz", "ucoz.com",
            "000webhostapp.com", "weebly.com", "wixsite.com", "wix.com",
            "blogspot.com", "wordpress.com",
            "infinityfree.net", "byet.org", "byethost.com", "epizy.com",
            "atspace.cc", "x10hosting.com", "freehostia.com",
        }

        # NOTE: Dev hosting is not automatically “safe”
        self.dev_hosting_domains = {
            "vercel.app",
            "netlify.app",
            "onrender.com",
            "herokuapp.com",
            "github.io",
            "repl.co",
            "replit.dev",
            "glitch.me",
        }

        self.suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".pw", ".link", ".gq"}

        # Brand/credential bait keywords
        self.phishing_keywords = {
            "login", "signin", "sign-in", "password", "credential",
            "verify", "verification", "confirm", "update", "secure", "security",
            "account", "unlock", "locked", "suspended", "restricted",
            "paypal", "microsoft", "office", "outlook", "google", "gmail", "amazon", "apple", "bank",
        }

        # URLhaus (no key)
        self.urlhaus_api = "https://urlhaus-api.abuse.ch/v1/url/"  # POST with form data {url=...}

        # Optional APIs
        self.gsb_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

    # -------------------------
    # Helpers
    # -------------------------
    @staticmethod
    def _normalize_url(url: str) -> str:
        url = (url or "").strip()
        if not url:
            return ""

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        p = urlparse(url)

        # Normalize: lowercase scheme/host, remove default ports, keep path/query/fragment
        scheme = (p.scheme or "https").lower()
        netloc = (p.netloc or "").strip().lower()

        # Remove credentials if any (user:pass@host) -> keep host only
        if "@" in netloc:
            netloc = netloc.split("@", 1)[1]

        # Remove default ports
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        if netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]

        return urlunparse((scheme, netloc, p.path or "/", p.params, p.query, p.fragment))

    @staticmethod
    def _host_only(netloc: str) -> str:
        # Remove port if any
        host = (netloc or "").lower()
        if ":" in host:
            host = host.split(":", 1)[0]
        if host.startswith("www."):
            host = host[4:]
        return host

    @staticmethod
    def _is_ip(host: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

    @staticmethod
    def _dedupe_keep_order(items):
        seen = set()
        out = []
        for x in items:
            if x and x not in seen:
                out.append(x)
                seen.add(x)
        return out

    @staticmethod
    def _vt_url_id(url: str) -> str:
        # VirusTotal URL identifier = urlsafe base64 without padding
        b = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
        return b.strip("=")

    # -------------------------
    # Heuristics
    # -------------------------
    def analyze_url_structure(self, url: str):
        score = 0.0
        risks = []

        p = urlparse(url)
        host = self._host_only(p.netloc)
        path = (p.path or "").lower()
        query = (p.query or "").lower()
        full = (url or "").lower()

        # 1) @ spoofing
        if "@" in full:
            score += 0.30
            risks.append("Contains '@' which is used for URL spoofing.")

        # 2) IP instead of domain
        if self._is_ip(host):
            score += 0.35
            risks.append("Uses an IP address instead of a domain.")

        # 3) Too many subdomains
        if host.count(".") >= 4:
            score += 0.18
            risks.append("Unusually deep subdomain chain.")

        # 4) Suspicious TLD
        for tld in self.suspicious_tlds:
            if host.endswith(tld):
                score += 0.18
                risks.append(f"Suspicious TLD detected ({tld}).")
                break

        # 5) Free hosting domain
        for d in self.free_hosting_domains:
            if host == d or host.endswith("." + d):
                score += 0.45
                risks.append(f"Free hosting / site-builder domain detected ({d}).")
                break

        # 6) Dev hosting domain (not automatically malicious, but higher risk for impersonation)
        for d in self.dev_hosting_domains:
            if host == d or host.endswith("." + d):
                score += 0.18
                risks.append(f"Dev hosting domain detected ({d}) — can host phishing pages.")
                break

        # 7) Brand impersonation signal: brand words on non-trusted roots
        brand_hits = []
        for kw in self.phishing_keywords:
            tokenized = full.replace("-", " ").replace("_", " ")
            if kw in tokenized:
                brand_hits.append(kw)

        if brand_hits:
            # if it’s not a trusted root, brands/cred keywords increase risk
            if not self._is_trusted_root(host):
                hit_count = len(set(brand_hits))
                score += min(0.35, 0.10 + 0.06 * hit_count)
                risks.append(f"Phishing/brand keywords present: {', '.join(sorted(set(brand_hits))[:8])}.")

        # 8) Long URL / obfuscation
        if len(url) >= 120:
            score += 0.12
            risks.append("Unusually long URL (possible obfuscation).")

        # 9) Suspicious file extensions
        if re.search(r"\.(htm|html|php|aspx)(\?|$)", path):
            score += 0.06
            risks.append("Webpage file extension in path (common in phishing kits).")

        # 10) Query contains credential-like params
        if re.search(r"(email=|user=|username=|pass=|password=|token=|session=)", query):
            score += 0.22
            risks.append("Query string contains credential/session-like parameters.")

        # 11) Non-HTTPS
        if not url.startswith("https://"):
            score += 0.12
            risks.append("Not using HTTPS.")

        return min(score, 0.99), self._dedupe_keep_order(risks)

    def _is_trusted_root(self, host: str) -> bool:
        # Trusted if host == root or subdomain of root
        for root in self.trusted_roots:
            if host == root or host.endswith("." + root):
                return True
        return False

    # -------------------------
    # Threat intel sources
    # -------------------------
    def check_urlhaus(self, url: str):
        try:
            r = requests.post(self.urlhaus_api, data={"url": url}, timeout=8)
            if r.status_code != 200:
                return 0.0, None

            data = r.json()
            # URLhaus returns ok + results when known
            if data.get("query_status") == "ok" and data.get("url_status") in {"online", "offline"}:
                return 0.90, "Flagged by URLhaus (known malicious URL)."
            return 0.0, None
        except Exception as e:
            logger.warning("URLhaus check failed: %s", e)
            return 0.0, None

    def check_google_safe_browsing(self, url: str):
        # Endpoint is POST /v4/threatMatches:find with key param [web:47]
        if not self.gsb_api_key:
            return 0.0, None

        try:
            api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
            payload = {
                "client": {"clientId": "phishguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            r = requests.post(api, json=payload, timeout=8)
            if r.status_code != 200:
                return 0.0, None

            data = r.json()
            if data.get("matches"):
                t = data["matches"][0].get("threatType", "UNKNOWN")
                return 0.90, f"Flagged by Google Safe Browsing ({t})."
            return 0.0, None
        except Exception as e:
            logger.warning("GSB check failed: %s", e)
            return 0.0, None

    def check_virustotal(self, url: str):
        # Proper flow: POST /api/v3/urls with form data 'url=...' [web:51]
        if not self.vt_api_key:
            return 0.0, None

        headers = {
            "accept": "application/json",
            "x-apikey": self.vt_api_key,
            "content-type": "application/x-www-form-urlencoded",
        }

        try:
            # Submit URL
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=f"url={url}",
                timeout=10,
            )
            if submit.status_code not in (200, 201):
                return 0.0, None

            # Fetch last analysis stats from URL object
            url_id = self._vt_url_id(url)
            detail = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"accept": "application/json", "x-apikey": self.vt_api_key},
                timeout=10,
            )
            if detail.status_code != 200:
                return 0.0, None

            data = detail.json()
            attrs = (data.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)

            if malicious >= 3:
                return 0.95, f"VirusTotal: malicious={malicious}, suspicious={suspicious}."
            if suspicious >= 3:
                return 0.75, f"VirusTotal: suspicious={suspicious}."
            return 0.0, None

        except Exception as e:
            logger.warning("VirusTotal check failed: %s", e)
            return 0.0, None

    # -------------------------
    # Main scan
    # -------------------------
    def scan(self, url: str):
        normalized = self._normalize_url(url)

        results = {
            "input_url": url,
            "url": normalized,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "domain": "",
            "confidence_score": 0.0,
            "threat_level": "SAFE",
            "risk_factors": [],
            "sources": {},
        }

        if not normalized:
            results["confidence_score"] = 0.50
            results["threat_level"] = "BORDERLINE"
            results["risk_factors"] = ["Empty URL input."]
            return results

        p = urlparse(normalized)
        host = self._host_only(p.netloc)
        results["domain"] = host

        # Trusted root short-circuit, BUT still explain why it’s safe
        if self._is_trusted_root(host):
            results["confidence_score"] = 0.02
            results["threat_level"] = "SAFE"
            results["risk_factors"] = ["Trusted domain."]
            results["sources"]["local_heuristics"] = {"confidence": 0.02, "risks": ["Trusted domain."]}
            return results

        # Local heuristics
        local_score, local_risks = self.analyze_url_structure(normalized)
        results["sources"]["local_heuristics"] = {
            "confidence": round(local_score, 2),
            "risks": local_risks,
        }

        # External sources
        urlhaus_score, urlhaus_risk = self.check_urlhaus(normalized)
        results["sources"]["urlhaus"] = {
            "confidence": round(urlhaus_score, 2),
            "message": urlhaus_risk or "Not flagged.",
        }

        gsb_score, gsb_risk = self.check_google_safe_browsing(normalized)
        results["sources"]["google_safe_browsing"] = {
            "confidence": round(gsb_score, 2),
            "message": gsb_risk or ("Not enabled." if not self.gsb_api_key else "Not flagged."),
        }

        vt_score, vt_risk = self.check_virustotal(normalized)
        results["sources"]["virustotal"] = {
            "confidence": round(vt_score, 2),
            "message": vt_risk or ("Not enabled." if not self.vt_api_key else "Not flagged."),
        }

        # Aggregate risks (so UI never ends up blank)
        risks = []
        risks.extend(local_risks)
        if urlhaus_risk:
            risks.append(urlhaus_risk)
        if gsb_risk:
            risks.append(gsb_risk)
        if vt_risk:
            risks.append(vt_risk)

        # If truly no risks, provide a safe explanation line
        if not risks:
            risks = ["No significant phishing indicators detected by heuristics/sources."]

        results["risk_factors"] = self._dedupe_keep_order(risks)

        # Weighted scoring (make heuristics matter most if APIs are missing)
        # Local 55%, URLhaus 25%, GSB 15%, VT 5%
        final_score = (
            local_score * 0.55 +
            urlhaus_score * 0.25 +
            gsb_score * 0.15 +
            vt_score * 0.05
        )
        final_score = min(final_score, 0.99)

        results["confidence_score"] = round(final_score, 2)

        if results["confidence_score"] >= 0.80:
            results["threat_level"] = "DANGEROUS"
        elif results["confidence_score"] >= 0.65:
            results["threat_level"] = "SUSPICIOUS"
        elif results["confidence_score"] >= 0.50:
            results["threat_level"] = "BORDERLINE"
        else:
            results["threat_level"] = "SAFE"

        return results


# Singleton for imports
scanner = URLPhishingScanner()


def scan_url(url: str):
    return scanner.scan(url)
