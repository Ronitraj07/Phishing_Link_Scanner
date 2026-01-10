// Theme Management
const savedTheme = localStorage.getItem('theme') || 'dark';
if (savedTheme === 'light') {
    document.body.classList.add('light-mode');
}

function toggleTheme() {
    document.body.classList.toggle('light-mode');
    const theme = document.body.classList.contains('light-mode') ? 'light' : 'dark';
    localStorage.setItem('theme', theme);
}

// History Management
let scanHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');

function addToHistory(url, result) {
    const timestamp = new Date().toLocaleTimeString();
    scanHistory.unshift({ url, result, timestamp });
    if (scanHistory.length > 5) {
        scanHistory.pop();
    }
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
        return `
            <div class="history-item">
                <span>${resultEmoji} ${item.url}</span>
                <span style="font-size: 0.8rem; color: rgba(241, 245, 249, 0.5);">${item.timestamp}</span>
            </div>
        `;
    }).join('');
}

// Initialize history on page load
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

    // Format the URL
    url = formatUrl(url);

    // Validate URL format
    if (!isValidUrl(url)) {
        showError('Please enter a valid URL (e.g., example.com or https://example.com)');
        return;
    }

    // Show loading state
    showLoading(true);
    hideResult();

    try {
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
        showLoading(false);
        displayResult(data, url);
        addToHistory(url, data.is_phishing ? 'Dangerous' : 'Safe');

    } catch (error) {
        showLoading(false);
        console.error('Error:', error);
        showError('Failed to scan URL. Please check your connection and try again.');
    }
}

// Handle Enter key press
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

    // Build details HTML
    if (data.details) {
        detailsHtml = `
            <div style="margin-top: 1.5rem; text-align: left; background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 8px; font-size: 0.95rem;">
                <p><strong>Analysis Details:</strong></p>
        `;
        
        if (data.details.confidence) {
            detailsHtml += `<p>• Confidence Score: ${Math.round(data.details.confidence * 100)}%</p>`;
        }
        
        if (data.details.risk_factors && data.details.risk_factors.length > 0) {
            detailsHtml += `<p>• Risk Factors: ${data.details.risk_factors.join(', ')}</p>`;
        }
        
        if (data.details.domain) {
            detailsHtml += `<p>• Domain: ${data.details.domain}</p>`;
        }
        
        detailsHtml += '</div>';
    }

    resultContent.innerHTML = `
        <div style="font-size: 3rem; margin-bottom: 1rem;">${resultIcon}</div>
        <h3 style="font-size: 1.5rem; margin-bottom: 0.75rem;">${resultTitle}</h3>
        <p style="font-size: 1.1rem; margin-bottom: 1rem;">${resultMessage}</p>
        <p style="font-size: 0.95rem; word-break: break-all; opacity: 0.9;">
            <strong>Scanned URL:</strong> ${url}
        </p>
        ${detailsHtml}
    `;

    resultContent.className = `${resultClass}`;
    resultBox.classList.remove('hidden');
    resultBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Show/Hide Loading
function showLoading(show) {
    const loading = document.getElementById('loading');
    if (show) {
        loading.classList.remove('hidden');
    } else {
        loading.classList.add('hidden');
    }
}

// Hide Result
function hideResult() {
    document.getElementById('result-box').classList.add('hidden');
}

// Show Error
function showError(message) {
    const resultBox = document.getElementById('result-box');
    const resultContent = document.getElementById('result');
    
    resultContent.innerHTML = `
        <div style="font-size: 3rem; margin-bottom: 1rem;">❌</div>
        <h3 style="font-size: 1.5rem; margin-bottom: 0.75rem; color: #ef4444;">ERROR</h3>
        <p style="font-size: 1.1rem;">${message}</p>
    `;
    
    resultContent.className = 'result-dangerous';
    resultBox.classList.remove('hidden');
}

// Smooth scrolling for navigation links
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
        const response = await fetch(`${window.API_URL}/api/health`);
        if (response.ok) {
            console.log('✅ Backend is connected and running');
        }
    } catch (error) {
        console.warn('⚠️ Backend might be offline:', error);
    }
});
