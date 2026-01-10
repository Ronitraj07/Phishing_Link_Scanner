import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    """Health check endpoint"""
    return {"status": "Backend is running!", "environment": os.getenv("ENV", "development")}

@app.get("/api/health")
def health_check():
    """Health check endpoint for deployment verification"""
    return {"status": "Backend is running!", "environment": os.getenv("ENV", "development")}

@app.get("/scan/")
def scan_endpoint(url: str):
    """Scan a URL for phishing indicators"""
    return scan_url(url)

@app.get("/api/scan")
def api_scan_endpoint(url: str):
    """API endpoint to scan a URL for phishing indicators"""
    return scan_url(url)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
