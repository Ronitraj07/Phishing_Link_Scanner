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
        self.trusted_domains = {
            "google.com", "microsoft.com", "apple.com", "facebook.com",
            "amazon.com", "github.com", "stackoverflow.com", "wikipedia.org",
            "youtube.com", "twitter.com", "linkedin.com", "reddit.com",
            "slack.com", "discord.com", "telegram.org", "gmail.com"
        }

        # HIGHLY SUSPICIOUS - FREE HOSTING
        self.free_hosting = {
            "ucoz.ua", "ucoz.ru", "ucoz.kz", "ucoz.com",
            "000webhostapp.com", "weebly.com", "wix.com", "wixsite.com",
            "blogspot.com", "wordpress.com", "tumblr.com",
            "infinityfree.net", "byet.org", "byethost.com", "epizy.com",
            "atspace.cc", "x10hosting.com", "freehostia.com", "phpnet.us",
            "awardspace.com", "110mb.com", "5gbfree.com"
        }

        # DEV HOSTING (suspicious if used for brand sites)
        self.dev_hosting = {
            "vercel.app", "netlify.app", "github.io", "heroku.com",
            "glitch.me", "replit.dev", "onrender.com", "herokuapp.com"
        }

        # SUSPICIOUS TLDS
        self.suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".pw", ".link",
            ".gq", ".download", ".review", ".bid", ".webcam", ".science"
        }

        # BRAND KEYWORDS
        self.brand_keywords = {
            "verify", "confirm", "authenticate", "validate", "authorize",
            "update", "urgent", "security", "secure", "account", "login",
            "signin", "password", "credential", "unlock", "locked",
            "suspended", "restricted", "action", "required", "immediately",
            "microsoft", "office", "outlook", "google", "gmail", "amazon",
            "apple", "facebook", "paypal", "bank", "ebay", "steam",
            "discord", "telegram", "whatsapp", "onedrive", "dropbox"
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
        """Aggressive heuristic analysis"""
        score = 0.0
        risks = []

        try:
            p = urlparse(url)
            domain = self._extract_domain(url)
            path = (p.path or "").lower()
            query = (p.query or "").lower()
            full_url = url.lower()

            # 1. @ SYMBOL (CRITICAL)
            if "@" in full_url:
                score += 0.35
                risks.append("🔴 Contains '@' symbol - domain spoofing attack detected")

            # 2. IP ADDRESS (CRITICAL)
            if self._is_ip(domain):
                score += 0.40
                risks.append("🔴 Uses IP address instead of domain - major red flag")

            # 3. FREE HOSTING DETECTION (VERY HIGH RISK)
            for free_domain in self.free_hosting:
                if domain == free_domain or domain.endswith("." + free_domain):
                    score += 0.50
                    risks.append(f"🔴 Free hosting domain detected: {free_domain} - commonly used for phishing")

                    # Check for brand impersonation on free hosting
                    for brand in ["microsoft", "apple", "google", "amazon", "paypal", "office"]:
                        if brand in domain or brand in path:
                            score += 0.30
                            risks.append(f"🔴 CRITICAL: Brand '{brand}' impersonation on free hosting")
                    break

            # 4. DEV HOSTING WITH BRAND NAMES
            for dev_domain in self.dev_hosting:
                if domain == dev_domain or domain.endswith("." + dev_domain):
                    # If brand names present, it's suspicious
                    for brand in ["microsoft", "google", "apple", "amazon", "paypal", "office"]:
                        if brand in domain or brand in path:
                            score += 0.25
                            risks.append(f"⚠️  Dev hosting + brand name: {brand} - possible impersonation")
                    break

            # 5. SUSPICIOUS TLDS
            for tld in self.suspicious_tlds:
                if domain.lower().endswith(tld):
                    score += 0.20
                    risks.append(f"⚠️  Suspicious TLD detected: {tld}")
                    break

            # 6. TOO MANY SUBDOMAINS
            if domain.count(".") > 3:
                score += 0.18
                risks.append("⚠️  Suspicious subdomain chain (deep nesting)")

            # 7. BRAND KEYWORDS IN URL
            keyword_matches = []
            for keyword in self.brand_keywords:
                if re.search(r"\b" + keyword + r"\b", full_url.replace("-", " ").replace("_", " ")):
                    keyword_matches.append(keyword)

            if len(keyword_matches) >= 3:
                score += 0.30
                risks.append(f"🔴 Multiple phishing keywords: {', '.join(keyword_matches[:5])}")
            elif len(keyword_matches) >= 2:
                score += 0.20
                risks.append(f"⚠️  Phishing keywords detected: {', '.join(keyword_matches)}")
            elif len(keyword_matches) == 1:
                score += 0.10
                risks.append(f"ℹ️  Phishing keyword found: {keyword_matches[0]}")

            # 8. LONG URL (OBFUSCATION)
            if len(url) > 150:
                score += 0.15
                risks.append(f"⚠️  Unusually long URL ({len(url)} chars) - possible obfuscation")

            # 9. QUERY PARAMETERS WITH CREDENTIALS
            if re.search(r"(email=|user=|username=|pass=|password=|token=|session=|auth=)", query):
                score += 0.30
                risks.append("🔴 Query contains credential-like parameters")

            # 10. SUSPICIOUS FILE EXTENSIONS
            if re.search(r"\.(htm|html|php|aspx|jsp|asp)(\?|#|$)", path):
                score += 0.12
                risks.append("⚠️  Webpage file in path (common in phishing kits)")

            # 11. ENCODED/UNICODE CHARACTERS
            if "%2f" in url or "%3a" in url or "xn--" in domain:
                score += 0.18
                risks.append("⚠️  URL contains encoded characters (obfuscation)")

            # 12. DOUBLE DOTS / UNUSUAL PATTERNS
            if ".." in domain or domain.count("-") > 5:
                score += 0.15
                risks.append("⚠️  Unusual domain pattern (too many hyphens/dots)")

            # 13. NO HTTPS
            if not url.startswith("https://"):
                score += 0.15
                risks.append("⚠️  Not using HTTPS encryption")

            # 14. SUSPICIOUS DOMAIN PATTERNS
            if re.search(r"(login|signin|verify|confirm|authenticate|update)-", domain):
                score += 0.25
                risks.append("🔴 Suspicious domain pattern (e.g., verify-account, login-here)")

            # 15. PORT NUMBERS
            if ":" in domain:
                port = domain.split(":")[-1]
                if not port in ["80", "443"]:
                    score += 0.12
                    risks.append(f"⚠️  Non-standard port detected: {port}")

            return min(score, 0.99), risks

        except Exception as e:
            logger.error(f"Heuristic analysis error: {e}")
            return 0.2, ["Analysis error"]

    def check_urlhaus(self, url):
        """Check URLhaus database"""
        try:
            resp = requests.post(self.urlhaus_api, data={"url": url}, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("url_status") in ["online", "offline"]:
                    return 0.95, "🔴 FLAGGED: URLhaus malicious URL database"
            return 0.0, None
        except Exception as e:
            logger.warning(f"URLhaus failed: {e}")
            return 0.0, None

    def check_google_safe_browsing(self, url):
        """Check Google Safe Browsing"""
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
                    threat_type = data["matches"][0].get("threatType", "UNKNOWN")
                    return 0.90, f"🔴 FLAGGED: Google Safe Browsing ({threat_type})"
            return 0.0, None
        except Exception as e:
            logger.warning(f"GSB failed: {e}")
            return 0.0, None

    def check_virustotal(self, url):
        """Check VirusTotal"""
        if not self.vt_api_key:
            return 0.0, None

        try:
            headers = {"x-apikey": self.vt_api_key}
            # Submit URL
            resp1 = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data=f"url={url}",
                timeout=10
            )
            if resp1.status_code not in [200, 201]:
                return 0.0, None

            # Get analysis
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp2 = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            if resp2.status_code != 200:
                return 0.0, None

            data = resp2.json()
            stats = ((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)

            if malicious >= 5:
                return 0.95, f"🔴 FLAGGED: VirusTotal - {malicious} vendors detected as malicious"
            elif malicious >= 2:
                return 0.80, f"⚠️  VirusTotal - {malicious} vendors flagged as suspicious"
            elif suspicious >= 5:
                return 0.70, f"⚠️  VirusTotal - {suspicious} vendors flagged as suspicious"

            return 0.0, None
        except Exception as e:
            logger.warning(f"VirusTotal failed: {e}")
            return 0.0, None

    def scan(self, url):
        """Main scanning function"""
        if not url or not url.strip():
            return {
                "url": url,
                "confidence_score": 0.0,
                "threat_level": "SAFE",
                "risk_factors": ["Empty URL"],
                "timestamp": datetime.utcnow().isoformat()
            }

        # Normalize URL
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

        # Quick trusted check
        if self._is_trusted(domain):
            result["confidence_score"] = 0.02
            result["threat_level"] = "SAFE"
            result["risk_factors"] = ["✅ Trusted domain"]
            return result

        # LOCAL HEURISTICS (55% weight)
        local_score, local_risks = self.analyze_url_structure(url)
        result["sources"]["local_heuristics"] = {
            "score": round(local_score, 2),
            "risks": local_risks
        }

        # URLHAUS (25% weight)
        urlhaus_score, urlhaus_msg = self.check_urlhaus(url)
        result["sources"]["urlhaus"] = {
            "score": round(urlhaus_score, 2),
            "message": urlhaus_msg or "Not flagged"
        }
        if urlhaus_msg:
            result["risk_factors"].append(urlhaus_msg)

        # GOOGLE SAFE BROWSING (15% weight)
        gsb_score, gsb_msg = self.check_google_safe_browsing(url)
        result["sources"]["gsb"] = {
            "score": round(gsb_score, 2),
            "message": gsb_msg or "Not enabled/flagged"
        }
        if gsb_msg:
            result["risk_factors"].append(gsb_msg)

        # VIRUSTOTAL (5% weight)
        vt_score, vt_msg = self.check_virustotal(url)
        result["sources"]["vt"] = {
            "score": round(vt_score, 2),
            "message": vt_msg or "Not enabled/flagged"
        }
        if vt_msg:
            result["risk_factors"].append(vt_msg)

        # Add local risks
        result["risk_factors"].extend(local_risks)
        result["risk_factors"] = list(set(result["risk_factors"]))  # Deduplicate

        # WEIGHTED FINAL SCORE
        final_score = (
            local_score * 0.55 +
            urlhaus_score * 0.25 +
            gsb_score * 0.15 +
            vt_score * 0.05
        )
        final_score = min(final_score, 0.99)
        result["confidence_score"] = round(final_score, 2)

        # Threat level
        if result["confidence_score"] >= 0.85:
            result["threat_level"] = "🔴 DANGEROUS"
        elif result["confidence_score"] >= 0.70:
            result["threat_level"] = "🟡 SUSPICIOUS"
        elif result["confidence_score"] >= 0.50:
            result["threat_level"] = "🟠 BORDERLINE"
        else:
            result["threat_level"] = "✅ SAFE"

        if not result["risk_factors"]:
            result["risk_factors"] = ["No significant threats detected"]

        return result


# Singleton
scanner = URLPhishingScanner()

def scan_url(url):
    return scanner.scan(url)
