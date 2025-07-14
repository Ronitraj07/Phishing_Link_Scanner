# **🔍 Phishing Link Scanner**  

🚀 A **super cool, modern, and interactive** phishing link scanner built with **FastAPI (Python)** for the backend and **HTML, CSS, JavaScript, Node.js** for the frontend.  

## **✨ Features**  
✅ **Beautiful UI** (Glassmorphism + Dark Mode)  
✅ **Real-time URL Scanning** (Basic phishing detection)  
✅ **Fast & Lightweight** (Uses FastAPI)  
✅ **Smooth Animations & Responsive Design**  

---

## **📂 Project Structure**
```
Phishing_Link_Scanner/
│-- backend/
│   ├── main.py          # FastAPI backend
│   ├── scanner.py       # Phishing detection logic
│
│-- frontend/
│   ├── index.html       # Website UI
│   ├── style.css        # Modern styling
│   ├── script.js        # JavaScript logic
│   ├── server.js        # Express.js frontend server
│-- README.md            # Project documentation
│-- requirements.txt     # Backend dependencies
│-- package.json         # Node.js dependencies
```

---

## **🛠️ Installation & Setup**

### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/Ronitraj07/Phishing_Link_Scanner.git
cd Phishing_Link_Scanner
```

---

### **2️⃣ Backend Setup (FastAPI)**
#### **🔹 Install Dependencies**
```bash
cd backend
pip install -r requirements.txt
```

#### **🔹 Run the Backend**
```bash
python main.py
```
✅ Backend should now be running at → [`http://127.0.0.1:8000`](http://127.0.0.1:8000)

---

### **3️⃣ Frontend Setup (Node.js & Express)**
#### **🔹 Install Dependencies**
```bash
cd frontend
npm install
```

#### **🔹 Run the Frontend**
```bash
node server.js
```
✅ Frontend should now be running at → [`http://127.0.0.1:3000`](http://127.0.0.1:3000)

---

## **🧪 How to Use**
1. Open **`http://127.0.0.1:3000`** in your browser  
2. Enter a **URL** and click **Scan**  
3. See if it's **Safe ✅** or **Suspicious ⚠️**  

---

## **📜 API Endpoints**
| Method | Endpoint | Description |
|--------|---------|-------------|
| `GET` | `/scan/?url=<URL>` | Scans a URL for phishing |

Example API call:  
```
http://127.0.0.1:8000/scan/?url=http://example.com
```

---

## **🤝 Contributing**
Want to improve the project? Feel free to **fork**, **star**, and submit a **pull request**. 🚀  

---

## **📜 License**
This project is **MIT Licensed**. Use freely and responsibly. 
