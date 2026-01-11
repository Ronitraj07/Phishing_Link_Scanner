import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner import scan_url
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="PhishGuard API", version="2.0.0")

# CORS Configuration - Allow your Vercel frontend
CORS_ORIGINS = [
    "https://phishing-ronitraj.vercel.app",
    "https://phishing-scanner.vercel.app",
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    """Root endpoint - verify API is running"""
    return {
        "status": "Backend is running!",
        "environment": os.getenv("ENV", "development"),
        "version": "2.0.0",
        "features": [
            "Multi-API phishing detection",
            "Enhanced confidence scoring",
            "Detailed risk analysis"
        ]
    }

@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "Backend is running!",
        "environment": os.getenv("ENV", "production"),
        "version": "2.0.0"
    }

@app.post("/api/scan")
def api_scan_endpoint(request: ScanRequest):
    """
    POST endpoint for URL scanning
    Returns comprehensive phishing analysis with confidence score
    """
    url = request.url
    logger.info(f"Scanning URL: {url}")
    
    try:
        result = scan_url(url)
        
        return {
            "url": result.get("url"),
            "is_phishing": result.get("is_phishing"),
            "status": result.get("status"),
            "details": {
                # Confidence: 0-1, where 1.0 = 100% certain
                "confidence": result.get("confidence", 0),
                "threat_indicators": result.get("threat_indicators", 0),
                "risk_factors": result.get("risk_factors", []),
                "domain": url.split('/')[2] if '/' in url else url
            },
            "scan_results": result.get("scan_results", []),
            "timestamp": result.get("timestamp")
        }
    except Exception as e:
        logger.error(f"Error scanning URL: {str(e)}")
        return {
            "url": url,
            "is_phishing": False,
            "status": "Error",
            "error": str(e),
            "details": {
                "confidence": 0,
                "risk_factors": [f"Scan error: {str(e)}"],
                "domain": url.split('/')[2] if '/' in url else url
            },
            "scan_results": []
        }

@app.get("/api/scan")
def api_scan_get(url: str):
    """
    GET endpoint for URL scanning (for testing)
    Returns comprehensive phishing analysis with confidence score
    """
    logger.info(f"Scanning URL (GET): {url}")
    
    try:
        result = scan_url(url)
        
        return {
            "url": result.get("url"),
            "is_phishing": result.get("is_phishing"),
            "status": result.get("status"),
            "details": {
                # Confidence: 0-1, where 1.0 = 100% certain
                "confidence": result.get("confidence", 0),
                "threat_indicators": result.get("threat_indicators", 0),
                "risk_factors": result.get("risk_factors", []),
                "domain": url.split('/')[2] if '/' in url else url
            },
            "scan_results": result.get("scan_results", []),
            "timestamp": result.get("timestamp")
        }
    except Exception as e:
        logger.error(f"Error scanning URL: {str(e)}")
        return {
            "url": url,
            "is_phishing": False,
            "status": "Error",
            "error": str(e),
            "details": {
                "confidence": 0,
                "risk_factors": [f"Scan error: {str(e)}"],
                "domain": url.split('/')[2] if '/' in url else url
            },
            "scan_results": []
        }

@app.get("/api/status")
def api_status():
    """
    Get API status and available checks
    """
    return {
        "status": "operational",
        "available_checks": {
            "local_heuristics": "Always enabled",
            "urlhaus": "Always enabled (free, no key required)",
            "google_safe_browsing": "Enabled" if os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") else "Disabled (API key required)",
            "virustotal": "Enabled" if os.getenv("VIRUSTOTAL_API_KEY") else "Disabled (API key required)"
        },
        "confidence_factors": {
            "local_heuristics": "20% weight",
            "urlhaus": "30% weight",
            "google_safe_browsing": "25% weight (if enabled)",
            "virustotal": "25% weight (if enabled)"
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
