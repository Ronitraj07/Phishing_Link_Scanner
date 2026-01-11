import requests
import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple
import os
from datetime import datetime

# ============ PHISHING DETECTION KEYWORDS & PATTERNS ============
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "bank", "account", "update", "password", 
    "confirm", "confirm-identity", "validate", "authenticate", "signin",
    "paypal", "amazon", "apple", "google", "microsoft", "steam",
    "blockchain", "crypto", "confirm-transaction", "verify-account"
]

SUSPICIOUS_PATTERNS = [
    r"^https?://.*@.*",  # URL with @ symbol
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address as domain
    r"https?://.*\..*\..*\..*\..{2,}/",  # Multiple subdomains
    r"https?://localhost",
    r"https?://127\.0\.0\.1",
]

LEGITIMATE_TLDS = [
    "com", "org", "net", "edu", "gov", "io", "co", "us", "uk", "de",
    "fr", "jp", "cn", "in", "au", "ca", "br", "ru", "it", "es"
]

# ============ VIRUSTOTAL API ============
def check_virustotal(url: str) -> Dict:
    """
    Check URL against VirusTotal database
    Free API: 4 requests/minute
    """
    try:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return {"success": False, "reason": "API key not configured", "malicious": 0, "suspicious": 0, "confidence": 0}
        
        headers = {"x-apikey": api_key}
        # URL encode the URL
        files = {"url": (None, url)}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            files=files,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            url_id = data.get("data", {}).get("id")
            
            if url_id:
                # Get analysis results
                analysis_response = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers,
                    timeout=10
                )
                
                if analysis_response.status_code == 200:
                    analysis = analysis_response.json()
                    stats = analysis.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    # Confidence: based on number of vendors flagging
                    total_vendors = stats.get("undetected", 0) + malicious + suspicious
                    confidence = (malicious + suspicious) / max(total_vendors, 1) if total_vendors > 0 else 0
                    
                    return {
                        "success": True,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "confidence": min(confidence, 1.0)
                    }
        
        return {"success": False, "reason": "API call failed", "malicious": 0, "suspicious": 0, "confidence": 0}
    except Exception as e:
        return {"success": False, "reason": str(e), "malicious": 0, "suspicious": 0, "confidence": 0}

# ============ URLHAUS API ============
def check_urlhaus(url: str) -> Dict:
    """
    Check URL against URLhaus (abuse.ch) database
    Free API, no authentication required
    """
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            query_status = data.get("query_status")
            
            if query_status == "ok":
                # URL found in database
                threat = data.get("threat", "")
                blacklisted = data.get("blacklists", {}).get("spamhaus_dbl", "not listed") != "not listed"
                
                confidence = 0.95 if blacklisted or "phishing" in threat.lower() else 0.7
                return {
                    "success": True,
                    "is_malicious": True,
                    "threat_type": threat,
                    "confidence": confidence
                }
            elif query_status == "not_found":
                return {"success": True, "is_malicious": False, "confidence": 0.1}
            else:
                return {"success": False, "reason": "Invalid query", "confidence": 0}
        
        return {"success": False, "reason": "API call failed", "confidence": 0}
    except Exception as e:
        return {"success": False, "reason": str(e), "confidence": 0}

# ============ GOOGLE SAFE BROWSING API ============
def check_google_safe_browsing(url: str) -> Dict:
    """
    Check URL against Google Safe Browsing API
    Requires API key from Google Cloud Console
    """
    try:
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        if not api_key:
            return {"success": False, "reason": "API key not configured", "is_safe": True, "confidence": 0}
        
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "phishing-scanner",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(endpoint, json=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            has_threats = bool(data.get("matches"))
            
            if has_threats:
                threat_types = [m.get("threatType") for m in data.get("matches", [])]
                confidence = 0.95 if "SOCIAL_ENGINEERING" in threat_types else 0.85
                return {
                    "success": True,
                    "is_safe": False,
                    "threat_types": threat_types,
                    "confidence": confidence
                }
            else:
                return {"success": True, "is_safe": True, "confidence": 0.9}
        
        return {"success": False, "reason": "API call failed", "is_safe": True, "confidence": 0}
    except Exception as e:
        return {"success": False, "reason": str(e), "is_safe": True, "confidence": 0}

# ============ PHISHING.AI API ============
def check_phishing_ai(url: str) -> Dict:
    """
    Check URL using Phishing.AI service
    Free API, no authentication required
    """
    try:
        response = requests.get(
            f"https://phishing.ai/api/check?url={url}",
            timeout=10,
            headers={"User-Agent": "PhishingScanner/1.0"}
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("is_phishing"):
                return {
                    "success": True,
                    "is_phishing": True,
                    "confidence": data.get("confidence", 0.8)
                }
            else:
                return {"success": True, "is_phishing": False, "confidence": 0.05}
        
        return {"success": False, "reason": "API call failed", "confidence": 0}
    except Exception as e:
        return {"success": False, "reason": str(e), "confidence": 0}

# ============ LOCAL HEURISTIC CHECKS ============
def check_url_heuristics(url: str) -> Tuple[int, float]:
    """
    Local heuristic checks without external APIs
    Returns: (risk_score, confidence)
    """
    risk_score = 0
    confidence = 0.0
    risk_factors = []
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check 1: Suspicious patterns (high confidence)
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url):
                risk_score += 25
                confidence += 0.25
                if "@" in url:
                    risk_factors.append("URL contains @ symbol (domain spoofing risk)")
                elif re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
                    risk_factors.append("Domain is IP address instead of hostname")
                elif "localhost" in url or "127.0.0.1" in url:
                    risk_factors.append("URL is localhost (development/internal)")
        
        # Check 2: Phishing keywords (medium confidence)
        keyword_count = sum(1 for keyword in PHISHING_KEYWORDS if keyword in path or keyword in domain)
        if keyword_count > 0:
            risk_score += min(15 * keyword_count, 30)
            confidence += min(0.15 * keyword_count, 0.3)
            risk_factors.append(f"Contains {keyword_count} phishing-related keywords")
        
        # Check 3: Domain reputation (medium confidence)
        if domain.count(".") > 3:  # Too many subdomains
            risk_score += 15
            confidence += 0.15
            risk_factors.append("Suspicious subdomain structure")
        
        # Check 4: HTTPS check (low confidence boost if missing)
        if not url.startswith("https://"):
            risk_score += 5
            confidence += 0.05
            risk_factors.append("Not using HTTPS encryption")
        
        # Check 5: Domain age simulation (check for new/suspicious TLDs)
        tld = domain.split(".")[-1].lower()
        if tld not in LEGITIMATE_TLDS and len(tld) > 3:
            risk_score += 10
            confidence += 0.1
            risk_factors.append(f"Uncommon TLD detected: {tld}")
        
        # Check 6: URL length (unusually long URLs are suspicious)
        if len(url) > 100:
            risk_score += 5
            confidence += 0.05
            risk_factors.append("Unusually long URL")
        
        # Normalize scores
        risk_score = min(risk_score, 100)
        confidence = min(confidence, 0.7)  # Heuristics alone max 70%
        
        return risk_score, confidence, risk_factors
    
    except Exception as e:
        return 0, 0, [f"Heuristic check error: {str(e)}"]

# ============ MAIN SCANNING FUNCTION ============
def scan_url(url: str) -> Dict:
    """
    Comprehensive URL scanning using multiple APIs and heuristics
    Returns combined results with weighted confidence scoring
    """
    
    # Validate URL
    if not url or not isinstance(url, str):
        return {
            "url": url,
            "status": "Invalid",
            "is_phishing": False,
            "confidence": 0.0,
            "risk_factors": ["Invalid or empty URL"],
            "scan_results": []
        }
    
    # Ensure URL has protocol
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    results = []
    threat_indicators = 0
    total_confidence = 0.0
    all_risk_factors = []
    
    # ========== API Checks ==========
    
    # 1. Local Heuristics (always run, fast)
    heuristic_score, heuristic_confidence, heuristic_factors = check_url_heuristics(url)
    results.append({
        "source": "Local Heuristics",
        "is_threat": heuristic_score > 50,
        "confidence": heuristic_confidence,
        "details": f"Risk score: {heuristic_score}/100"
    })
    total_confidence += heuristic_confidence * 0.20  # 20% weight
    if heuristic_score > 50:
        threat_indicators += 1
    all_risk_factors.extend(heuristic_factors)
    
    # 2. URLhaus (fast, reliable, free)
    urlhaus_result = check_urlhaus(url)
    if urlhaus_result.get("success"):
        is_malicious = urlhaus_result.get("is_malicious", False)
        urlhaus_confidence = urlhaus_result.get("confidence", 0)
        results.append({
            "source": "URLhaus (abuse.ch)",
            "is_threat": is_malicious,
            "confidence": urlhaus_confidence,
            "details": urlhaus_result.get("threat_type", "")
        })
        total_confidence += urlhaus_confidence * 0.30  # 30% weight
        if is_malicious:
            threat_indicators += 1
            all_risk_factors.append("Flagged by URLhaus abuse database")
    
    # 3. Google Safe Browsing (if API key available)
    if os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"):
        gsb_result = check_google_safe_browsing(url)
        if gsb_result.get("success"):
            is_threat = not gsb_result.get("is_safe", True)
            gsb_confidence = gsb_result.get("confidence", 0)
            results.append({
                "source": "Google Safe Browsing",
                "is_threat": is_threat,
                "confidence": gsb_confidence,
                "details": ", ".join(gsb_result.get("threat_types", []))
            })
            total_confidence += gsb_confidence * 0.25  # 25% weight
            if is_threat:
                threat_indicators += 1
                all_risk_factors.append("Flagged by Google Safe Browsing")
    
    # 4. VirusTotal (if API key available)
    if os.getenv("VIRUSTOTAL_API_KEY"):
        vt_result = check_virustotal(url)
        if vt_result.get("success"):
            malicious_count = vt_result.get("malicious", 0)
            suspicious_count = vt_result.get("suspicious", 0)
            vt_confidence = vt_result.get("confidence", 0)
            
            is_threat = malicious_count > 0 or suspicious_count > 3
            results.append({
                "source": "VirusTotal",
                "is_threat": is_threat,
                "confidence": vt_confidence,
                "details": f"{malicious_count} malicious, {suspicious_count} suspicious vendors"
            })
            total_confidence += vt_confidence * 0.25  # 25% weight
            if is_threat:
                threat_indicators += 1
                all_risk_factors.append(f"Detected by {malicious_count + suspicious_count} security vendors")
    
    # ========== DECISION LOGIC ==========
    
    # Final confidence is weighted average
    final_confidence = min(total_confidence, 0.99)  # Cap at 99%
    
    # Threat determination: based on number of sources flagging + confidence threshold
    is_phishing = False
    status = "Safe"
    
    if threat_indicators >= 2:
        # Multiple sources flagging = definitely phishing
        is_phishing = True
        status = "Dangerous"
        final_confidence = min(max(final_confidence, 0.85), 0.99)
    elif threat_indicators == 1 and final_confidence > 0.60:
        # Single source + high confidence = suspicious
        is_phishing = True
        status = "Suspicious"
        final_confidence = min(final_confidence, 0.80)
    elif final_confidence > 0.75:
        # High local confidence = suspicious
        is_phishing = True
        status = "Suspicious"
    else:
        # Safe
        status = "Safe"
        final_confidence = 1.0 - final_confidence  # Invert for safe URLs
    
    # Remove duplicates in risk factors
    all_risk_factors = list(set(all_risk_factors))
    
    return {
        "url": url,
        "status": status,
        "is_phishing": is_phishing,
        "confidence": round(final_confidence, 3),
        "threat_indicators": threat_indicators,
        "risk_factors": all_risk_factors,
        "scan_results": results,
        "timestamp": datetime.now().isoformat()
    }
