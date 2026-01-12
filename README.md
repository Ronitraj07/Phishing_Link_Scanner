# 🛡️ PhishGuard – Phishing Link Scanner

PhishGuard is a modern phishing link scanner web application designed to help users identify potentially malicious or phishing URLs before visiting them.  
It provides a clean, interactive UI along with a FastAPI-powered backend to analyze URLs and display risk indicators in real time.

🌐 **Live Website:**  
https://phishing-ronitraj.vercel.app/

📂 **GitHub Repository:**  
https://github.com/Ronitraj07/Phishing_Link_Scanner

---

## 🚀 Features

- 🔍 Scan any URL for phishing indicators  
- 📊 Confidence score with visual risk bar  
- ⚠️ Displays detected risk factors  
- 🕒 Recent scan history in the UI  
- 📱 Fully responsive (mobile + desktop)  
- 🎨 Modern glassmorphism UI with animations  
- 📚 Educational sections explaining phishing risks  
- ⚡ Fast API response using FastAPI backend  

---

## 🧠 Why PhishGuard?

Phishing remains one of the most common cyber-attacks used to steal credentials, financial data, and personal information.  
PhishGuard aims to:

- Reduce accidental visits to malicious links  
- Educate users about phishing techniques  
- Provide quick risk analysis without relying only on browser warnings  

This project is built with **both security awareness and usability** in mind.

---

## 🏗️ Project Structure

```

Phishing_Link_Scanner/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── scanner.py           # Phishing detection logic
│   ├── requirements.txt     # Python dependencies
│
├── frontend/
│   ├── index.html           # Main UI
│   ├── style.css            # Styling (dark UI + glass effect)
│   ├── script.js            # Frontend logic
│   ├── server.js            # Express server (local use)
│
├── package.json             # Node dependencies
├── README.md
└── .gitignore

````

---

## 🛠️ Tech Stack

| Layer | Technology |
|------|------------|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python (FastAPI) |
| API Communication | REST |
| Hosting | Vercel (Frontend) |
| Local Server | Node.js + Express |

---

## ⚙️ Installation & Setup (For Review / Local Testing)

> ⚠️ This project is **not open-source**.  
> The following steps are provided **only for personal testing, review, or demonstration purposes**.

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Ronitraj07/Phishing_Link_Scanner.git
cd Phishing_Link_Scanner
````

---

### 2️⃣ Backend Setup (FastAPI)

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend will run at:

```
http://127.0.0.1:8000
```

---

### 3️⃣ Frontend Setup (Optional – Local)

```bash
cd frontend
npm install
node server.js
```

Frontend will be available at:

```
http://127.0.0.1:3000
```

---

## 🔌 API Usage

### Scan a URL

```
GET /scan/?url=<URL>
```

Example:

```
http://127.0.0.1:8000/scan/?url=https://example.com
```

---

## 🧪 How It Works

1. User enters a URL in the scanner
2. Frontend sends the URL to the backend API
3. Backend analyzes common phishing indicators
4. API returns:

   * Threat level
   * Confidence score
   * Risk factors
5. Frontend displays results visually

---

## 📈 Planned Enhancements

* Advanced detection logic / ML-based scoring
* Browser extension version
* User-based scan history
* Integration with threat-intelligence feeds
* Exportable scan reports

---

## ⚠️ Usage & Rights

**This project is proprietary and owned by the repository author.**

* ❌ Not free to use commercially
* ❌ Not permitted to redistribute or resell
* ❌ Not permitted to deploy as your own service
* ✅ Viewing and reviewing the code is allowed
* ✅ Educational reference with attribution only

For permissions or collaboration, please contact the repository owner.

---

## 🔒 License

**All rights reserved.**

No part of this project may be copied, modified, distributed, or used for commercial purposes without explicit permission from the author.

