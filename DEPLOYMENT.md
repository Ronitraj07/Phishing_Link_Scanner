# Deployment Guide: Phishing Link Scanner

## 📋 Quick Overview

- **Frontend**: Hosted on Vercel
- **Backend**: Hosted on Render
- **Frontend**: HTML/CSS/JavaScript (static)
- **Backend**: FastAPI with CORS enabled

---

## 🚀 Step 1: Deploy Backend to Render

### 1.1 Go to Render.com
1. Visit https://render.com
2. Sign up or log in with GitHub

### 1.2 Create a New Web Service
1. Click **"New +"** → **"Web Service"**
2. Authorize GitHub access
3. Select your **"Phishing_Link_Scanner"** repository
4. Fill in the configuration:
   - **Name**: `phishing-scanner-backend` (or any name you prefer)
   - **Environment**: Python 3
   - **Region**: Choose the region closest to you
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app`
   - **Instance Type**: Free tier (sufficient for testing)

### 1.3 Add Environment Variables
1. Click **"Advanced"** in the deployment settings
2. Add these environment variables:
   - **FRONTEND_URL**: Leave empty for now (you'll update after frontend is deployed)
   - **ENV**: `production`
   - **PORT**: `8000`

3. Click **"Create Web Service"**
4. Wait 5-10 minutes for deployment to complete

### 1.4 Get Your Backend URL
Once deployed, Render will show you a URL like:
```
https://phishing-scanner-backend.onrender.com
```

✅ **Save this URL!** You'll need it for the frontend.

### 1.5 Test Backend
Open in browser or terminal:
```bash
curl https://phishing-scanner-backend.onrender.com/api/health
```

Expected response:
```json
{"status": "Backend is running!", "environment": "production"}
```

---

## 🚀 Step 2: Deploy Frontend to Vercel

### 2.1 Go to Vercel.com
1. Visit https://vercel.com
2. Sign up or log in with GitHub

### 2.2 Import Your Repository
1. Click **"Add New"** → **"Project"**
2. Click **"Import"** next to your repository
3. Select **"Phishing_Link_Scanner"**

### 2.3 Configure Deployment
1. **Framework Preset**: Select **"Other"** or **"Static Site"** (it's just HTML/JS)
2. **Root Directory**: Set to **"frontend"**
3. **Build Command**: Leave empty (no build needed for static)
4. **Output Directory**: Leave empty

### 2.4 Add Environment Variables
In the project settings page, add:
- **Name**: `API_URL`
- **Value**: `https://phishing-scanner-backend.onrender.com` (your backend URL from Step 1.4)
- **Environments**: Select all (Production, Preview, Development)

### 2.5 Deploy
Click **"Deploy"** and wait 2-3 minutes for completion.

### 2.6 Get Your Frontend URL
Vercel will show you a URL like:
```
https://phishing-scanner.vercel.app
```

✅ **Save this URL!** You need to update backend CORS settings with this.

---

## 🔗 Step 3: Connect Frontend to Backend

### 3.1 Update Backend CORS Settings
1. Go to **Render Dashboard** → Select your backend service
2. Click **"Environment"** tab
3. Edit the **`FRONTEND_URL`** variable and set it to your Vercel URL:
   ```
   https://phishing-scanner.vercel.app
   ```
4. Click **"Save"**
5. Backend will automatically redeploy (wait 1-2 minutes)

### 3.2 Test Connection
Open your frontend URL in browser and try scanning a URL. Check browser console (F12) for errors.

---

## ✅ Testing Your Deployment

### Test 1: Backend Health Check
```bash
curl https://phishing-scanner-backend.onrender.com/api/health
```
Expected: `{"status": "Backend is running!", ...}`

### Test 2: Frontend Load
Open: `https://phishing-scanner.vercel.app`
Expected: Website loads without errors

### Test 3: Full Integration
1. Open your frontend URL
2. Enter any URL
3. Click "Scan"
4. Should get a response from backend

### Debugging
If Test 3 fails:
1. Open browser console (F12 → Console tab)
2. Look for error messages
3. Common issues:
   - CORS error: Update CORS settings in backend
   - Network error: Check if backend URL is correct
   - API_URL not set: Check Vercel environment variables

---

## 🔄 Auto-Deployment (GitHub)

Now that everything is deployed, here's how updates work:

### To Update Backend:
1. Make changes to files in `backend/` folder
2. Commit and push to GitHub:
   ```bash
   git add backend/
   git commit -m "Fix: Update backend logic"
   git push origin main
   ```
3. Render automatically detects changes and redeploys (2-5 minutes)

### To Update Frontend:
1. Make changes to files in `frontend/` folder
2. Commit and push to GitHub:
   ```bash
   git add frontend/
   git commit -m "Fix: Update UI"
   git push origin main
   ```
3. Vercel automatically detects changes and redeploys (1-2 minutes)

---

## 📝 Environment Variables Reference

### Backend (Render Environment Variables)
| Variable | Value | Notes |
|----------|-------|-------|
| `FRONTEND_URL` | `https://your-vercel-app.vercel.app` | Your Vercel frontend URL |
| `ENV` | `production` | Set to production for live |
| `PORT` | `8000` | Default port for FastAPI |

### Frontend (Vercel Environment Variables)
| Variable | Value | Notes |
|----------|-------|-------|
| `API_URL` | `https://your-backend.onrender.com` | Your Render backend URL |

---

## 🛠️ Troubleshooting

### Frontend shows blank page
- Check Vercel deployment logs (Dashboard → Deployments)
- Check browser console for JavaScript errors
- Verify API_URL is set correctly

### Backend returns 500 error
- Check Render logs (Dashboard → Logs)
- Verify all dependencies in requirements.txt are installed
- Check environment variables are set

### CORS error in console
- Make sure FRONTEND_URL in backend matches your Vercel URL exactly
- No trailing slashes!
- Redeploy backend after updating CORS

### Free tier keeps going to sleep
- Render free tier becomes dormant after 15 minutes of inactivity
- First request after sleep takes ~30 seconds
- Upgrade to Starter tier ($7/month) for always-on

---

## 📊 Monitoring Your Deployment

### Render Dashboard
- Check logs for errors: Dashboard → Your Service → Logs
- Monitor CPU/Memory usage
- Set up alerts for failures

### Vercel Dashboard
- Check build logs: Dashboard → Your Project → Deployments
- View analytics and performance
- Monitor error rates

---

## 🔐 Best Practices

1. **Never commit `.env` files** - they contain secrets
2. **Use `.env.example`** - commit this instead
3. **Test locally first** - before pushing to GitHub
4. **Check logs** - when deployment fails
5. **Document changes** - in commit messages
6. **Keep dependencies updated** - regularly

---

## 📞 Quick Links

- Render Dashboard: https://dashboard.render.com
- Vercel Dashboard: https://vercel.com/dashboard
- Backend Health: `https://phishing-scanner-backend.onrender.com/api/health`
- Frontend: `https://phishing-scanner.vercel.app`

---

## ✨ You're All Set!

Your Phishing Link Scanner is now live on the internet! 

**Frontend**: https://phishing-scanner.vercel.app  
**Backend**: https://phishing-scanner-backend.onrender.com

Congratulations! 🎉
