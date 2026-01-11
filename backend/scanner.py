import os
import re
import logging
from datetime import datetime
from urllib.parse import urlparse

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLPhishingScanner:
    def __init__(self):
        # ONLY ABSOLUTELY TRUSTED DOMAINS
        self.trusted_domains = {
            "google.com", "microsoft.com", "apple.com", "amazon.com",
            "github.com", "stackoverflow.com", "wikipedia.org",
            "facebook.com", "youtube.com", "twitter.com"
        }

        # 🚨 CRITICAL: FREE HOSTING = AUTOMATIC HIGH RISK
        self.free_hosting = {
            "ucoz.ua", "ucoz.ru", "ucoz.kz", "ucoz.com",
            "000webhostapp.com", "weebly.com", "wix.com", "wixsite.com",
            "blogspot.com", "wordpress.com", "tumblr.com",
            "infinityfree.net", "byet.org", "byethost.com", "epizy.com",
            "atspace.cc", "x10hosting.com", "freehostia.com", "phpnet.us",
            "awardspace.com", "110mb.com", "5gbfree.com", "000webhost.com"
        }

        # SUSPICIOUS TLDS
        self.suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".pw", ".link",
            ".gq", ".download", ".review", ".bid", ".webcam", ".science"
        }

        # PHISHING KEYWORDS - VERY AGGRESSIVE
        self.phishing_keywords = {
            "verify", "confirm", "authenticate", "validate",
            "update", "urgent", "action", "required", "immediately",
            "account", "login", "signin", "password", "credential",
            "unlock", "locked", "suspended", "restricted", "expire",
            "microsoft", "office", "outlook", "google", "gmail",
            "amazon", "apple", "facebook", "paypal", "ebay", "bank"
        }

        self.urlhaus_api = "https://urlhaus-api.abuse.ch/v1/url/"
        self.gsb_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

    def _extract_domain(self, url):
        try:
            p = urlparse(url)
            host = (p.netloc or "").lower()
            if "@" in host:
                host = host.split("@")[1]
            if host.startswith("www."):
                host = host[4:]
            return host
        except:
            return ""

    def _is_trusted(self, domain):
        for trusted in self.trusted_domains:
            if domain == trusted or domain.endswith("." + trusted):
                return True
        return False

    def _is_ip(self, domain):
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain))

    def analyze_url_structure(self, url):
        """AGGRESSIVE PHISHING DETECTION"""
        score = 0.0
        risks = []

        try:
            p = urlparse(url)
            domain = self._extract_domain(url)
            path = (p.path or "").lower()
            query = (p.query or "").lower()
            full_url = url.lower()

            # 🔴 CRITICAL: @ SYMBOL
            if "@" in full_url:
                score += 0.40
                risks.append("🔴 CRITICAL: URL contains '@' - domain spoofing detected")

            # 🔴 CRITICAL: IP ADDRESS
            if self._is_ip(domain):
                score += 0.45
                risks.append("🔴 CRITICAL: Uses IP address instead of domain")

            # 🔴 CRITICAL: FREE HOSTING DOMAIN
            for free_domain in self.free_hosting:
                if domain == free_domain or domain.endswith("." + free_domain):
                    score += 0.55  # MASSIVE SCORE
                    risks.append(f"🔴 CRITICAL: Free hosting domain '{free_domain}' - phishing indicator")
                    
                    # DOUBLE CHECK: if brand names present, EVEN WORSE
                    for brand in ["microsoft", "apple", "google", "amazon", "paypal", "office", "bank", "login", "verify"]:
                        if brand in domain or brand in path:
                            score += 0.25
                            risks.append(f"🔴 CRITICAL: Brand/credential keyword '{brand}' on free hosting")
                    break

            # 🟡 SUSPICIOUS TLD
            for tld in self.suspicious_tlds:
                if domain.lower().endswith(tld):
                    score += 0.25
                    risks.append(f"🟡 Suspicious TLD detected: {tld}")
                    break

            # 🟡 TOO MANY SUBDOMAINS
            if domain.count(".") > 3:
                score += 0.20
                risks.append("🟡 Suspicious subdomain chain detected")

            # 🔴 PHISHING KEYWORDS (AGGRESSIVE)
            keyword_matches = []
            for keyword in self.phishing_keywords:
                if re.search(r"\b" + re.escape(keyword) + r"\b", full_url.replace("-", " ").replace("_", " ")):
                    keyword_matches.append(keyword)

            if len(keyword_matches) >= 4:
                score += 0.40
                risks.append(f"🔴 CRITICAL: Multiple phishing keywords: {', '.join(keyword_matches[:5])}")
            elif len(keyword_matches) >= 2:
                score += 0.25
                risks.append(f"🟡 Phishing keywords detected: {', '.join(keyword_matches[:3])}")
            elif len(keyword_matches) == 1:
                score += 0.12
                risks.append(f"ℹ️ Keyword detected: {keyword_matches[0]}")

            # 🔴 LONG URL (OBFUSCATION)
            if len(url) > 150:
                score += 0.18
                risks.append(f"🟡 Unusually long URL ({len(url)} chars)")

            # 🔴 QUERY CREDENTIALS
            if re.search(r"(email=|user=|username=|pass=|password=|token=|session=)", query):
                score += 0.35
                risks.append("🔴 CRITICAL: Query contains credential parameters")

            # 🟡 FILE EXTENSIONS
            if re.search(r"\.(htm|html|php|aspx|jsp)(\?|#|$)", path):
                score += 0.15
                risks.append("🟡 Webpage file in path (phishing kit indicator)")

            # 🟡 ENCODED CHARACTERS
            if "%2f" in url or "%3a" in url or "xn--" in domain:
                score += 0.20
                risks.append("🟡 URL contains encoded characters")

            # 🟡 NO HTTPS
            if not url.startswith("https://"):
                score += 0.18
                risks.append("🟡 Not using HTTPS encryption")

            # 🟡 SUSPICIOUS DOMAIN PATTERNS
            if re.search(r"(login|signin|verify|confirm|authenticate|update|urgent)-", domain):
                score += 0.22
                risks.append("🟡 Suspicious domain pattern detected")

            # 🟡 EXCESS HYPHENS
            if domain.count("-") > 5:
                score += 0.15
                risks.append("🟡 Excessive hyphens in domain")

            return min(score, 0.99), risks

        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return 0.3, ["Error during analysis"]

    def check_urlhaus(self, url):
        try:
            resp = requests.post(self.urlhaus_api, data={"url": url}, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("url_status"):
                    return 0.95, "🔴 Flagged in URLhaus malicious database"
            return 0.0, None
        except Exception as e:
            logger.warning(f"URLhaus check failed: {e}")
            return 0.0, None

    def check_google_safe_browsing(self, url):
        if not self.gsb_api_key:
            return 0.0, None

        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
            payload = {
                "client": {"clientId": "phishguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            resp = requests.post(api_url, json=payload, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("matches"):
                    threat = data["matches"][0].get("threatType", "UNKNOWN")
                    return 0.92, f"🔴 Google Safe Browsing flagged: {threat}"
            return 0.0, None
        except Exception as e:
            logger.warning(f"GSB check failed: {e}")
            return 0.0, None

    def check_virustotal(self, url):
        if not self.vt_api_key:
            return 0.0, None

        try:
            headers = {"x-apikey": self.vt_api_key}
            resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=f"url={url}",
                timeout=10
            )
            if resp.status_code not in [200, 201]:
                return 0.0, None

            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            detail = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            if detail.status_code != 200:
                return 0.0, None

            data = detail.json()
            stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)

            if malicious >= 5:
                return 0.88, f"🔴 VirusTotal: {malicious} vendors flagged as malicious"
            return 0.0, None

        except Exception as e:
            logger.warning(f"VirusTotal check failed: {e}")
            return 0.0, None

    def scan(self, url):
        """MAIN SCANNING ENGINE"""
        if not url or not url.strip():
            return {
                "url": url,
                "domain": "",
                "confidence_score": 0.0,
                "threat_level": "SAFE",
                "risk_factors": ["Empty URL"],
                "timestamp": datetime.utcnow().isoformat()
            }

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        domain = self._extract_domain(url)

        result = {
            "url": url,
            "domain": domain,
            "confidence_score": 0.0,
            "threat_level": "SAFE",
            "risk_factors": [],
            "sources": {},
            "timestamp": datetime.utcnow().isoformat()
        }

        # TRUSTED QUICK EXIT
        if self._is_trusted(domain):
            result["confidence_score"] = 0.01
            result["threat_level"] = "✅ SAFE"
            result["risk_factors"] = ["✅ Trusted domain"]
            return result

        # LOCAL HEURISTICS (60% weight - AGGRESSIVE)
        local_score, local_risks = self.analyze_url_structure(url)
        result["sources"]["local_heuristics"] = {
            "score": round(local_score, 2),
            "risks": local_risks
        }

        # URLHAUS (20% weight)
        urlhaus_score, urlhaus_msg = self.check_urlhaus(url)
        result["sources"]["urlhaus"] = {
            "score": round(urlhaus_score, 2),
            "message": urlhaus_msg or "Not flagged"
        }
        if urlhaus_msg:
            result["risk_factors"].append(urlhaus_msg)

        # GSB (12% weight)
        gsb_score, gsb_msg = self.check_google_safe_browsing(url)
        result["sources"]["gsb"] = {
            "score": round(gsb_score, 2),
            "message": gsb_msg or "Not enabled/flagged"
        }
        if gsb_msg:
            result["risk_factors"].append(gsb_msg)

        # VT (8% weight)
        vt_score, vt_msg = self.check_virustotal(url)
        result["sources"]["vt"] = {
            "score": round(vt_score, 2),
            "message": vt_msg or "Not enabled/flagged"
        }
        if vt_msg:
            result["risk_factors"].append(vt_msg)

        # ADD LOCAL RISKS
        result["risk_factors"].extend(local_risks)
        result["risk_factors"] = list(set(result["risk_factors"]))

        # WEIGHTED FINAL SCORE
        final_score = (
            local_score * 0.60 +
            urlhaus_score * 0.20 +
            gsb_score * 0.12 +
            vt_score * 0.08
        )
        final_score = min(final_score, 0.99)
        result["confidence_score"] = round(final_score, 2)

        # THREAT LEVELS
        if result["confidence_score"] >= 0.80:
            result["threat_level"] = "🔴 DANGEROUS"
        elif result["confidence_score"] >= 0.65:
            result["threat_level"] = "🟡 SUSPICIOUS"
        elif result["confidence_score"] >= 0.50:
            result["threat_level"] = "🟠 BORDERLINE"
        else:
            result["threat_level"] = "✅ SAFE"

        if not result["risk_factors"]:
            result["risk_factors"] = ["✅ No significant phishing indicators detected"]

        return result


scanner = URLPhishingScanner()

def scan_url(url):
    return scanner.scan(url)
