import requests
from urllib.parse import urlparse
import re
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLPhishingScanner:
    def __init__(self):
        # Known safe domains
        self.safe_domains = {
            'google.com', 'facebook.com', 'amazon.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'youtube.com', 'twitter.com', 'linkedin.com', 'microsoft.com',
            'apple.com', 'cloudflare.com', 'vercel.app', 'render.com', 'heroku.com',
            'reddit.com', 'slack.com', 'discord.com', 'telegram.org', 'gmail.com'
        }
        
        # HIGHLY SUSPICIOUS FREE HOSTING DOMAINS
        self.free_hosting_domains = {
            'ucoz.ua', 'ucoz.ru', 'ucoz.kz', 'ucoz.com',  # UCoz
            '000webhostapp.com', 'weebly.com', 'wix.com',   # Free website builders (often misused)
            'blogspot.com', 'wordpress.com', 'pages.github.io',  # Blog platforms
            'netlify.app', 'vercel.app', 'heroku.com',      # Dev hosting (sometimes misused)
            'repl.it', 'glitch.me', 'onrender.com',
            'free-hosting.com', 'x10hosting.com', 'infinityfree.net',
            'byethost.com', 'hostinger.com', 'byet.org',
            'epizy.com', 'atspace.cc', 'freehostia.com'
        }
        
        # Phishing keywords
        self.phishing_keywords = {
            'verify', 'confirm', 'authenticate', 'validate', 'authorize',
            'update', 'urgent', 'action', 'immediately', 'required',
            'account', 'login', 'signin', 'password', 'credential',
            'bank', 'paypal', 'apple', 'microsoft', 'google', 'amazon',
            'confirmation', 'suspended', 'locked', 'restricted', 'expire',
            'unusual', 'suspicious', 'activity', 'unusual activity',
            'click here', 'confirm identity', 'verify account'
        }
        
        # URLhaus API (no key needed)
        self.urlhaus_api = "https://urlhaus-api.abuse.ch/v1/url/"
        
        # Google Safe Browsing API (if key available)
        self.gsb_api_key = None
        try:
            import os
            self.gsb_api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        except:
            pass
        
        # VirusTotal API (if key available)
        self.vt_api_key = None
        try:
            import os
            self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        except:
            pass

    def analyze_url_structure(self, url):
        """Analyze URL structure for phishing indicators"""
        score = 0
        risks = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()
            
            # 1. CHECK FOR @ SYMBOL (domain spoofing)
            if '@' in url:
                score += 0.25
                risks.append("Contains @ symbol - possible domain spoofing")
            
            # 2. CHECK FOR IP ADDRESS INSTEAD OF DOMAIN
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}', domain):
                score += 0.30
                risks.append("URL uses IP address instead of domain name")
            
            # 3. CHECK FOR SUSPICIOUS SUBDOMAINS (many dots)
            if domain.count('.') > 3:
                score += 0.20
                risks.append("Suspicious number of subdomains")
            
            # 4. CHECK TLD SUSPICION
            if domain.endswith(('.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.pw', '.link', '.gq')):
                score += 0.15
                risks.append("Uncommon/free TLD detected")
            
            # 5. CHECK FOR FREE HOSTING DOMAINS
            for free_domain in self.free_hosting_domains:
                if free_domain in domain:
                    score += 0.35  # VERY SUSPICIOUS
                    risks.append(f"Free hosting domain detected: {free_domain}")
                    
                    # EXTRA CHECK: if it contains brand names in path
                    for brand in ['microsoft', 'apple', 'google', 'amazon', 'facebook', 'paypal']:
                        if brand in path or brand in domain:
                            score += 0.20  # DOUBLE RED FLAG
                            risks.append(f"Brand name '{brand}' in free hosting URL - likely phishing")
                    break
            
            # 6. CHECK FOR URL LENGTH > 100 chars (obfuscation)
            if len(url) > 100:
                score += 0.10
                risks.append("URL is unusually long (>100 chars)")
            
            # 7. CHECK FOR PHISHING KEYWORDS IN FULL URL
            keyword_count = 0
            for keyword in self.phishing_keywords:
                if keyword in full_url.replace('-', ' ').replace('_', ' '):
                    keyword_count += 1
            
            if keyword_count >= 2:
                score += 0.20
                risks.append(f"Multiple phishing keywords detected ({keyword_count})")
            elif keyword_count == 1:
                score += 0.10
                risks.append(f"Phishing keyword detected")
            
            # 8. CHECK FOR PORT NUMBERS (unusual ports)
            if ':' in domain and not domain.endswith(':80') and not domain.endswith(':443'):
                score += 0.15
                risks.append("Unusual port number detected")
            
            # 9. CHECK FOR ENCODED CHARACTERS OR OBFUSCATION
            if '%' in url or 'xn--' in domain:  # punycode
                score += 0.15
                risks.append("URL contains encoded/unicode characters")
            
            # 10. CHECK FOR BRAND IMPERSONATION (major brands on suspicious domains)
            major_brands = ['microsoft', 'apple', 'google', 'amazon', 'facebook', 'paypal', 'bank', 'ebay']
            for brand in major_brands:
                if brand in domain or brand in path:
                    # If on free hosting or unknown domain, HIGH RISK
                    if domain not in self.safe_domains:
                        score += 0.25
                        risks.append(f"Possible brand impersonation: {brand}")
            
            # 11. CHECK FOR HTTPS (legitimate sites use it)
            if not url.startswith('https://'):
                score += 0.10
                risks.append("Not using HTTPS encryption")
            
            # 12. CHECK FOR SUSPICIOUS PATTERNS IN DOMAIN
            # Patterns like google-login, verify-account, etc.
            if re.search(r'(login|verify|confirm|authenticate|update|urgent|action)-', domain):
                score += 0.20
                risks.append("Suspicious domain pattern detected")
            
            # 13. CHECK FOR EXCESS HYPHENS (often in phishing URLs)
            if domain.count('-') > 3:
                score += 0.12
                risks.append("Excessive hyphens in domain")
            
            return min(score, 0.99), risks
            
        except Exception as e:
            logger.error(f"Error analyzing URL structure: {e}")
            return 0.5, ["Error analyzing URL"]

    def check_urlhaus(self, url):
        """Check URLhaus phishing database"""
        try:
            response = requests.post(self.urlhaus_api, data={'url': url}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('query_status') == 'ok' and data.get('results'):
                    # URL found in URLhaus (it's phishing!)
                    return 0.85, "Flagged in URLhaus phishing database"
            return 0, None
        except Exception as e:
            logger.error(f"URLhaus check failed: {e}")
            return 0, None

    def check_google_safe_browsing(self, url):
        """Check Google Safe Browsing API"""
        if not self.gsb_api_key:
            return 0, None
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
            payload = {
                "client": {
                    "clientId": "phishguard",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            response = requests.post(api_url, json=payload, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('matches'):
                    return 0.80, f"Flagged by Google Safe Browsing: {data['matches'][0]['threatType']}"
            return 0, None
        except Exception as e:
            logger.error(f"Google Safe Browsing check failed: {e}")
            return 0, None

    def check_virustotal(self, url):
        """Check VirusTotal for malicious URLs"""
        if not self.vt_api_key:
            return 0, None
        
        try:
            headers = {"x-apikey": self.vt_api_key}
            params = {"url": url}
            response = requests.get("https://www.virustotal.com/api/v3/urls", headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    stats = data['data'][0]['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    if malicious > 5:  # More than 5 vendors flagged it
                        return 0.90, f"Flagged by {malicious} security vendors on VirusTotal"
            return 0, None
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return 0, None

    def scan(self, url):
        """Main scanning function with weighted scores"""
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "confidence_score": 0.0,
            "threat_level": "SAFE",
            "risk_factors": [],
            "sources": {}
        }
        
        # Validate URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Quick check against safe domains
        domain = urlparse(url).netloc.lower().replace('www.', '')
        if domain in self.safe_domains:
            results["confidence_score"] = 0.02
            results["threat_level"] = "SAFE"
            return results
        
        # 1. LOCAL HEURISTICS (40% weight) - AGGRESSIVE
        local_score, local_risks = self.analyze_url_structure(url)
        results["sources"]["local_heuristics"] = {
            "confidence": local_score,
            "risks": local_risks
        }
        
        # 2. URLHAUS CHECK (30% weight)
        urlhaus_score, urlhaus_risk = self.check_urlhaus(url)
        if urlhaus_risk:
            results["risk_factors"].append(urlhaus_risk)
        results["sources"]["urlhaus"] = {
            "confidence": urlhaus_score,
            "message": urlhaus_risk or "Not in database"
        }
        
        # 3. GOOGLE SAFE BROWSING (20% weight)
        gsb_score, gsb_risk = self.check_google_safe_browsing(url)
        if gsb_risk:
            results["risk_factors"].append(gsb_risk)
        results["sources"]["google_safe_browsing"] = {
            "confidence": gsb_score,
            "message": gsb_risk or "Not flagged"
        }
        
        # 4. VIRUSTOTAL (10% weight)
        vt_score, vt_risk = self.check_virustotal(url)
        if vt_risk:
            results["risk_factors"].append(vt_risk)
        results["sources"]["virustotal"] = {
            "confidence": vt_score,
            "message": vt_risk or "Not detected"
        }
        
        # Calculate weighted average
        # LOCAL: 40%, URLHAUS: 30%, GSB: 20%, VT: 10%
        final_score = (
            local_score * 0.40 +
            urlhaus_score * 0.30 +
            gsb_score * 0.20 +
            vt_score * 0.10
        )
        
        results["confidence_score"] = round(min(final_score, 0.99), 2)
        
        # Determine threat level
        if results["confidence_score"] >= 0.80:
            results["threat_level"] = "DANGEROUS"
        elif results["confidence_score"] >= 0.65:
            results["threat_level"] = "SUSPICIOUS"
        elif results["confidence_score"] >= 0.50:
            results["threat_level"] = "BORDERLINE"
        else:
            results["threat_level"] = "SAFE"
        
        # Add local risks to overall risks
        results["risk_factors"].extend(local_risks)
        
        return results

# Initialize scanner
scanner = URLPhishingScanner()

def scan_url(url):
    """API endpoint function"""
    return scanner.scan(url)
