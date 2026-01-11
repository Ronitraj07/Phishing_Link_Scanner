import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner import scan_url

app = FastAPI()

# CORS Configuration - Allow your Vercel frontend
CORS_ORIGINS = [
    "https://phishing-ronitraj.vercel.app",  # Your Vercel deployment
    "http://localhost:3000",  # Local development
    "http://localhost:8000",
    "http://localhost:5173",  # Vite dev server
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
    return {"status": "Backend is running!", "environment": os.getenv("ENV", "development")}

@app.get("/api/health")
def health_check():
    return {"status": "Backend is running!", "environment": os.getenv("ENV", "production")}

@app.post("/api/scan")
def api_scan_endpoint(request: ScanRequest):
    url = request.url
    result = scan_url(url)
    
    is_dangerous = "Dangerous" in result.get("status", "") or "Suspicious" in result.get("status", "")
    
    return {
        "url": url,
        "is_phishing": is_dangerous,
        "status": result.get("status", "Unknown"),
        "details": {
            "confidence": 0.85 if is_dangerous else 0.5,
            "risk_factors": result.get("risk_factors", []),
            "domain": url.split('/')[2] if '/' in url else url
        }
    }

@app.get("/api/scan")
def api_scan_get(url: str):
    result = scan_url(url)
    
    is_dangerous = "Dangerous" in result.get("status", "") or "Suspicious" in result.get("status", "")
    
    return {
        "url": url,
        "is_phishing": is_dangerous,
        "status": result.get("status", "Unknown"),
        "details": {
            "confidence": 0.85 if is_dangerous else 0.5,
            "risk_factors": result.get("risk_factors", []),
            "domain": url.split('/')[2] if '/' in url else url
        }
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
