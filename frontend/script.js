// API Configuration - UPDATED TO CORRECT BACKEND
window.API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8000'
    : 'https://phishing-link-scanner-1.onrender.com';

console.log('✅ API URL configured:', window.API_URL);

// Theme Management
const body = document.body;
const themeBtn = document.querySelector('.theme-toggle');
const savedTheme = localStorage.getItem('theme') || 'dark';

if (savedTheme === 'light') {
    body.classList.add('light-mode');
    updateThemeIcon();
}

function updateThemeIcon() {
    const icon = themeBtn.querySelector('i');
    if (body.classList.contains('light-mode')) {
        icon.classList.remove('fa-moon');
        icon.classList.add('fa-sun');
    } else {
        icon.classList.remove('fa-sun');
        icon.classList.add('fa-moon');
    }
}

function toggleTheme() {
    body.classList.toggle('light-mode');
    const theme = body.classList.contains('light-mode') ? 'light' : 'dark';
    localStorage.setItem('theme', theme);
    updateThemeIcon();
}

if (themeBtn) {
    themeBtn.addEventListener('click', toggleTheme);
}

// History Management
let scanHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');

function addToHistory(url, result) {
    const timestamp = new Date().toLocaleTimeString();
    scanHistory.unshift({ url, result, timestamp });
    if (scanHistory.length > 5) scanHistory.pop();
    localStorage.setItem('scanHistory', JSON.stringify(scanHistory));
    displayHistory();
}

function displayHistory() {
    const historyList = document.getElementById('history-list');
    if (scanHistory.length === 0) {
        historyList.innerHTML = '<p style="color: rgba(241, 245, 249, 0.5); font-size: 0.9rem;">No scans yet</p>';
        return;
    }
    
    historyList.innerHTML = scanHistory.map((item, index) => {
        const resultEmoji = item.result.includes('Safe') ? '✅' : '⚠️';
        const shortUrl = item.url.length > 40 ? item.url.substring(0, 40) + '...' : item.url;
        return `
            <div class="history-item">
                <span>${resultEmoji} ${shortUrl}</span>
                <span style="font-size: 0.8rem; color: rgba(241, 245, 249, 0.5);">${item.timestamp}</span>
            </div>
        `;
    }).join('');
}

displayHistory();

// URL Validation
function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function formatUrl(urlString) {
    if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
        urlString = 'https://' + urlString;
    }
    return urlString;
}

// Main Scanning Function
async function scanUrl() {
    const urlInput = document.getElementById('urlInput');
    let url = urlInput.value.trim();

    if (!url) {
        showError('Please enter a URL to scan');
        return;
    }

    url = formatUrl(url);

    if (!isValidUrl(url)) {
        showError('Please enter a valid URL (e.g., example.com or https://example.com)');
        return;
    }

    showLoading(true);
    hideResult();

    try {
        console.log('🔍 Scanning:', url);
        console.log('📡 Backend:', window.API_URL);
        
        const response = await fetch(`${window.API_URL}/api/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('✅ Response:', data);
        showLoading(false);
        displayResult(data, url);
        addToHistory(url, data.is_phishing ? 'Dangerous' : 'Safe');

    } catch (error) {
        showLoading(false);
        console.error('❌ Error:', error);
        showError('Failed to scan URL. Backend may be waking up (~30 seconds on first request).');
    }
}

function handleKeyPress(event) {
    if (event.key === 'Enter') {
        scanUrl();
    }
}

// Display Results
function displayResult(data, url) {
    const resultBox = document.getElementById('result-box');
    const resultContent = document.getElementById('result');

    let resultClass = '';
    let resultTitle = '';
    let resultMessage = '';
    let resultIcon = '';
    let detailsHtml = '';

    if (data.is_phishing) {
        resultClass = 'result-dangerous';
        resultTitle = '⚠️ WARNING: PHISHING DETECTED';
        resultMessage = 'This URL appears to be a phishing website. DO NOT enter your credentials or personal information.';
        resultIcon = '🚨';
    } else {
        resultClass = 'result-safe';
        resultTitle = '✅ SAFE URL';
        resultMessage = 'This URL appears to be legitimate and safe to visit.';
        resultIcon = '🛡️';
    }

    if (data.details) {
        detailsHtml = `
            <div style="margin-top: 1.5rem; text-align: left; background: rgba(0,0,0,0.3); padding: 1.25rem; border-radius: 12px; font-size: 0.95rem;">
                <p style="font-weight: 700; margin-bottom: 0.75rem;">📊 Analysis Details:</p>
        `;
        
        if (data.details.confidence) {
            detailsHtml += `<p style="margin-bottom: 0.5rem;">• Confidence Score: ${Math.round(data.details.confidence * 100)}%</p>`;
        }
        
        if (data.details.risk_factors && data.details.risk_factors.length > 0) {
            detailsHtml += `<p style="margin-bottom: 0.5rem;">• Risk Factors: ${data.details.risk_factors.join(', ')}</p>`;
        }
        
        if (data.status) {
            detailsHtml += `<p style="margin-bottom: 0.5rem;">• Status: ${data.status}</p>`;
        }
        
        detailsHtml += '</div>';
    }

    resultContent.innerHTML = `
        <div style="font-size: 4rem; margin-bottom: 1.25rem;">${resultIcon}</div>
        <h3 style="font-size: 1.6rem; margin-bottom: 1rem; font-weight: 800;">${resultTitle}</h3>
        <p style="font-size: 1.15rem; margin-bottom: 1.5rem; line-height: 1.6;">${resultMessage}</p>
        <div style="font-size: 0.9rem; word-break: break-all; opacity: 0.9; background: rgba(0,0,0,0.3); padding: 1.15rem; border-radius: 12px; font-family: 'Courier New', monospace;">
            <strong>🔗 Scanned URL:</strong><br>
            <span style="color: var(--primary-light);">${url}</span>
        </div>
        ${detailsHtml}
    `;

    resultContent.className = `result-content ${resultClass}`;
    resultBox.classList.remove('hidden');
    resultBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showLoading(show) {
    const loading = document.getElementById('loading');
    if (show) {
        loading.classList.remove('hidden');
    } else {
        loading.classList.add('hidden');
    }
}

function hideResult() {
    document.getElementById('result-box').classList.add('hidden');
}

function showError(message) {
    const resultBox = document.getElementById('result-box');
    const resultContent = document.getElementById('result');
    
    resultContent.innerHTML = `
        <div style="font-size: 4rem; margin-bottom: 1.25rem;">❌</div>
        <h3 style="font-size: 1.6rem; margin-bottom: 1rem; color: #ef4444; font-weight: 800;">ERROR</h3>
        <p style="font-size: 1.15rem; line-height: 1.6;">${message}</p>
    `;
    
    resultContent.className = 'result-content result-dangerous';
    resultBox.classList.remove('hidden');
}

document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Health check on page load
window.addEventListener('load', async () => {
    try {
        console.log('🔍 Checking backend health...');
        const response = await fetch(`${window.API_URL}/api/health`);
        if (response.ok) {
            const data = await response.json();
            console.log('✅ Backend is connected and running!', data);
        }
    } catch (error) {
        console.warn('⚠️ Backend might be offline or waking up. API URL:', window.API_URL);
    }
});
