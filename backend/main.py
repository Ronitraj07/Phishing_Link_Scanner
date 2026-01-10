import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner import scan_url

app = FastAPI()

# Dynamic CORS configuration
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

CORS_ORIGINS = [
    FRONTEND_URL,  # Vercel frontend URL from environment
    "http://localhost:3000",  # Local development
    "http://localhost:8000",  # Local backend
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8000",
    "https://phishing-scanner.vercel.app",  # Production frontend
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request model for POST requests
class ScanRequest(BaseModel):
    url: str

@app.get("/")
def read_root():
    """Health check endpoint"""
    return {"status": "Backend is running!", "environment": os.getenv("ENV", "development")}

@app.get("/api/health")
def health_check():
    """Health check endpoint for deployment verification"""
    return {"status": "Backend is running!", "environment": os.getenv("ENV", "development")}

@app.post("/api/scan")
def api_scan_endpoint(request: ScanRequest):
    """API endpoint to scan a URL for phishing indicators - POST method"""
    url = request.url
    result = scan_url(url)
    
    # Convert response to match frontend expectations
    return {
        "url": url,
        "is_phishing": "Dangerous" in result.get("status", "") or "Suspicious" in result.get("status", ""),
        "status": result.get("status", "Unknown"),
        "details": {
            "confidence": 0.85 if "Dangerous" in result.get("status", "") else 0.5,
            "risk_factors": [],
            "domain": url
        }
    }

@app.get("/api/scan")
def api_scan_get(url: str):
    """API endpoint to scan a URL for phishing indicators - GET method (fallback)"""
    result = scan_url(url)
    
    # Convert response to match frontend expectations
    return {
        "url": url,
        "is_phishing": "Dangerous" in result.get("status", "") or "Suspicious" in result.get("status", ""),
        "status": result.get("status", "Unknown"),
        "details": {
            "confidence": 0.85 if "Dangerous" in result.get("status", "") else 0.5,
            "risk_factors": [],
            "domain": url
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
